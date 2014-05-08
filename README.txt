Software Power Meter using RAPL feature

This utility implements a software power meter. This uses Linux Intel® RAPL
(Running Average Power Limit) driver using power capping sysfs.
Intel RAPL driver and power cap sysfs is available from Linux kernel 3.13
release.

Usage:  rapl_power_meter [ ... ]
  --help Display this usage information.
  --version Show version.
  --no-daemon No daemon.
  --interface
  --hostname
  --index.html specify local index.html path
  --port

By default rapl power meter starts as a Linux daemon, unless no-daemon mode
is specified.
The default port is 9999, which can be changed by command line option.
This program binds to localhost only, unless an interface is specified via
command line option.

There is a default index.html is built into this program, which can be changed
by command line option (A sample is provided for reference).
The command line option hostname can be used to specify server path in
index.html. Some proxy's expects domain names in the hostname to route
requests.

Since this utility only allows ready only access to power capping sysfs,so no
root privilege is required.

Operation

This utility starts a mini http server and waits for "GET" requests. Each GET
request can have one of the following paths:
/rapl_domains_count : Returns number of power cap domains present. Each domain
is an independent power unit, where power can be measured.
/rapl_domain_name/_domain_number/_sub_domain_number_: Domains are organized in
a hierarchical model. A domain can contain multiple sub domains. Refer to
documentation of Linux Power Cap sysfs under kernel tree documentation. Using
the path domain names can be obtained. For example /rapl_domain_name/1, returns
name for domain one, and /rapl_domain_name/1/1 returns name for sub domain 1,
under domain 1.
/rapl_domain_energy/_domain_number/_sub_domain_number_: Returns domain energy.
The path follows same model as rapl_domain_name.
/rapl_domain_max_energy_domain_number/_sub_domain_number_: Returns maximum
possible energy. The path follows same model as rapl_domain_name.

Default index.html
This utility has an in built web page, which uses above http GET requests to
calculate power and display. It calculates power for all available domains
and sub domains and displays in table, which is updated inline.
This uses java script and AJAX to send GET request and update values.
Also there is a logging feature, which when enabled logs all power and allows
download of log data in a CSV format.

Release:
v1.0 : Base release
