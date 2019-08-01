from __future__ import print_function

import io
import json
import os
import re
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

import requests
import yaml


CACHE_MAX_AGE = 3600


class LogError(object):
    def __init__(self, ref, url, job_name, filename=None, error_lines=[]):
        self.ref = ref
        self.url = url
        self.job_name = job_name
        self.filename = filename
        self.error_lines = error_lines

    def __str__(self):
        return '[{}] {}\nurl: {}\nfile: {}\n{}\n'.format(
            self.ref, self.job_name, self.url, self.filename or '',
            "\n".join(self.error_lines))

    def __repr__(self):
        return ('<LogError ref={} job_name={} filename={} error_lines={} '
                'lines>'.format(self.ref, self.job_name, self.filename,
                                len(self.error_lines)))


class LogAnalyzer(object):
    def __init__(self, config=None):
        self.tox_error_start_re = re.compile(
            r'(Failed \d+ tests - output below:'
            r'|Failures during discovery'
            r')')

        self.tox_error_end_re = re.compile(
            r' ERROR: ')

        self.log_line_re = re.compile(
            r'^((?P<date>\w{3} [0-9 ]{2} \d{2}:\d{2}:\d{2}(.\d{3,6})?) '
            r'(?P<hostname>[a-zA-Z0-9_.-]+) '
            r'(?P<service>[a-zA-Z0-9_.@-]*)'
            r'\[(?P<pid>\d+)\]: )?'
            r'((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}) \d+ )?'
            r'(?P<log>.*)$')

        extra_regexps = "".join([
            "|{}".format(r)
            for r in config.get('error_log_regexps', [])])

        self.log_match_re = re.compile(
            r'(^ERROR'
            r'{}'
            r')'.format(extra_regexps))

    def _get_log_errors(self, fp):
        lines = []

        for l in fp:
            line = l.decode('utf-8').rstrip()
            m = self.log_line_re.match(line)
            if not m:
                continue
            d = m.groupdict()

            m = self.log_match_re.search(d['log'])
            if m:
                lines.append(line)

        return lines

    def _get_tempest_errors_from_tox(self, fp):
        lines = []

        tree = ET.parse(fp)
        root = tree.getroot()
        for e in root.findall('testcase'):
            e_fail = e.find('failure')
            if e_fail is not None:
                lines.append("Test %s.%s failed:" % (e.attrib['classname'],
                                                     e.attrib['name']))
                lines.append(e_fail.text.rstrip())
                lines.append('')

        return lines

    def _get_tox_errors(self, fp):
        tox_error_flag = False

        lines = []

        for l in fp:
            line = l.strip().decode('utf-8')
            if not tox_error_flag:
                m = self.tox_error_start_re.search(line)
                if m:
                    tox_error_flag = True
            else:
                m = self.tox_error_end_re.search(line)
                if m:
                    tox_error_flag = False
                else:
                    lines.append(line)

        return lines


class DownstreamLogAnalyzer(LogAnalyzer):
    def __init__(self, url, config=None):
        super(DownstreamLogAnalyzer, self).__init__(config=config)

        self.config = config

        self.url = url

        self.job_name_re = re.compile('/job/(?P<job_name>[^/]*)/')

    def _download(self, url, dest):

        if os.path.exists(dest):
            mtime = os.stat(dest).st_mtime
            now = time.time()
            if mtime + CACHE_MAX_AGE > now:
                print("Reading {} from cache.".format(url))
                return

        dirname = os.path.dirname(dest)
        if not os.path.exists(dirname):
            os.makedirs(dirname, 0o755)

        print("Downloading {}.".format(url))

        r = requests.get(url, stream=True)
        # TODO(gthiemonge) check if file size is equal to Content-length header
        with open(dest, 'wb') as fp:
            for chunk in r.iter_content(chunk_size=1024*1024):
                fp.write(chunk)

    def _get_log_files(self):
        r = requests.get(self.url)
        content = r.text

        file_list = []

        link_re = re.compile('<a href="(?P<url>[^"]*)"')
        for m in link_re.findall(content):
            if m.endswith('.tar.gz'):
                file_list.append(m)

        file_path_list = []

        for l in file_list:
            log_url = "%s/%s" % (self.url, l)
            dest = os.path.expanduser(
                os.path.join(self.config['cache_dir'],
                             self.url.replace('https://', ''),
                             l))

            self._download(log_url, dest)
            file_path_list.append(dest)

        return file_path_list

    def _get_log_file_errors(self, path):

        m = self.job_name_re.search(self.url)
        job_name = m.groupdict().get('job_name')

        errors = []

        try:
            tf = tarfile.open(path, 'r:gz')
            for tarinfo in tf:
                for f in self.config['log_files']:
                    if ('/var/log/containers/' in tarinfo.name and
                            tarinfo.name.endswith(f)):
                        fp = tf.extractfile(tarinfo.name)
                        lines = self._get_log_errors(fp)
                        if lines:
                            err = LogError(ref='downstream', url=self.url,
                                           job_name=job_name,
                                           filename=tarinfo.name,
                                           error_lines=lines)
                            errors.append(err)
                        break
                if ('tempest-results-' in tarinfo.name and
                        tarinfo.name.endswith('.xml')):
                    fp = tf.extractfile(tarinfo.name)
                    lines = self._get_tempest_errors_from_tox(fp)
                    if lines:
                        err = LogError(ref='downstream', url=self.url,
                                       job_name=job_name,
                                       filename=tarinfo.name,
                                       error_lines=lines)
                        errors.append(err)
        except IOError as e:
            print("Error while reading {}".format(path))
            raise e

        return errors

    def get_errors(self):
        log_files = self._get_log_files()

        errors = []
        for log_file in log_files:
            errors.extend(self._get_log_file_errors(log_file))

        return errors


class OpendevReviewLogAnalyzer(LogAnalyzer):
    def __init__(self, change, config=None):
        super(OpendevReviewLogAnalyzer, self).__init__(
            config=config)

        self.change = change

        self.files = config['log_files']

        message_failure_regexp = (
            r'(?P<url>https?://[^ ]*) : FAILURE in (?:\d+h )?(?:\d+m )?\d{2}s')

        if not config.get('include_non_voting_jobs', False):
            message_failure_regexp += r'(?! \(non-voting\))'

        self.message_failure_re = re.compile(message_failure_regexp)

        self.job_name_re = re.compile('/(check|gate)/(?P<job_name>[^/]*)/')

    def _get_failed_jobs(self):
        r = requests.get(
            'https://review.opendev.org/changes/{}/detail'.format(
                self.change))
        content = r.text.split('\n', 1)[1]

        d = json.loads(content)

        urls = []

        for message in d['messages'][::-1]:
            for url in self.message_failure_re.findall(message['message']):
                if url.startswith(
                        'https://zuul.opendev.org/t/openstack/build/'):
                    build_id = url.split('/')[-1]
                    r = requests.get('https://zuul.opendev.org/api/tenant/'
                                     'openstack/build/{}'.format(build_id))
                    url = r.json()['log_url']

                urls.append(url)
            if urls:
                break

        return urls

    def _get_job_errors(self, url):
        if url[-1] != '/':
            url += '/'

        errors = []

        m = self.job_name_re.search(url)
        job_name = m.groupdict().get('job_name')

        prefix = ''
        for p in ('controller',):
            r = requests.get('{}{}/'.format(url, p))
            if r.status_code == 200:
                prefix = p + '/'
                break

        for f in self.files:
            log_url = '{}{}logs/{}'.format(url, prefix, f)
            r = requests.get(log_url)
            fp = io.BytesIO(r.content)
            lines = self._get_log_errors(fp)
            if lines:
                err = LogError(ref=self.change, url=url, job_name=job_name,
                               filename=f, error_lines=lines)
                errors.append(err)

        for ext in ('', '.gz'):
            log_url = '{}job-output.txt{}'.format(url, ext)
            r = requests.get(log_url)
            fp = io.BytesIO(r.content)
            lines = self._get_tox_errors(fp)
            if lines:
                err = LogError(ref=self.change, url=url, job_name=job_name,
                               filename=f, error_lines=lines)
                errors.append(err)

        if not errors:
            errors.append(LogError(ref=self.change, url=url,
                                   job_name=job_name))

        return errors

    def get_errors(self):
        urls = self._get_failed_jobs()

        errors = []
        for url in urls:
            errors.extend(self._get_job_errors(url))

        return errors


class OptionError(Exception):
    pass


class ConfigError(Exception):
    pass


class Config(object):
    def __init__(self):
        self.global_config = {}

    def _config_path(self):
        for f in ("log_analyzer.yml",
                  os.path.expanduser("~/.config/log_analyzer.yml"),
                  os.path.expanduser("~/.log_analyzer.yml"),
                  "/etc/log_analyzer.yml"):
            yield f

    def _read_config_file(self):
        for config_file in self._config_path():
            if os.path.exists(config_file):
                with open(config_file) as fp:
                    self.global_config = yaml.safe_load(fp.read())
                break
        else:
            raise ConfigError("Cannot find config file")

    def get_module_config(self, module):
        self._read_config_file()

        if 'sources' not in self.global_config:
            raise OptionError(
                "No sources defined in configuration file")

        if module not in self.global_config['sources']:
            raise OptionError(
                "Cannot find '{module}' module in configuration".format(
                    module=module))
        config = self.global_config['sources'][module]

        return config

    def get_log_analyzer_class(self, module):
        config = self.global_config['sources'][module]

        if 'type' not in config:
            raise OptionError(
                "No 'type' field in module configuration file")

        this_module = sys.modules[__name__]

        if not hasattr(this_module, config['type']):
            raise OptionError("Module '{module}' doesn't exist".format(
                module=config['type']))

        cls = getattr(this_module, config['type'])
        if not issubclass(cls, LogAnalyzer):
            raise OptionError("Invalid '{module}' module type".format(
                module=module))

        return cls


def main():
    try:
        module = sys.argv[1]
        ref = sys.argv[2]
    except IndexError:
        print("usage: %s <module> <ref>" % (sys.argv[0]))
        sys.exit(1)

    global_config = Config()

    try:
        config = global_config.get_module_config(module)

        cls = global_config.get_log_analyzer_class(module)
    except OptionError as e:
        print(e)
        sys.exit(1)

    log_analyzer = cls(ref, config=config)

    for error in log_analyzer.get_errors():
        print(error)


if __name__ == "__main__":
    main()
