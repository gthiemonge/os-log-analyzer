===============
os-log-analyzer
===============

A tool to analyze CI error logs.

Modules
~~~~~~~

2 modules are provided in this repository:

* OpendevReviewLogAnalyzer: analyze logs from https://review.opendev.org's
  changes.

* DownstreamLogAnalyzer: analyze Red Hat OSP CI logs.

Configuration
~~~~~~~~~~~~~

Configuration file ``log_analyzer.yml`` contains sample configuration for the
Octavia project.


Usage
~~~~~

::

    os-log-analyzer upstream <change_number>

    os-log-analyzer downstream https://url/to/build/artefact/
