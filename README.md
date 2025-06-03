# ANY.RUN

Publisher: ANYRUN FZCO \
Connector Version: 1.4.1 \
Product Vendor: ANYRUN FZCO \
Product Name: ANY.RUN \
Minimum Product Version: 6.3.0

This app enables you to detonate files and URLs, and perform investigative actions, using the ANY.RUN interactive online malware sandbox service, thereby giving you automated analysis and advanced threat detection through an agentless sandbox

## Authentication

This connector requires an API key to authenticate with the ANY.RUN services. You can generate the key at your [ANY.RUN Profile](https://app.any.run/profile).\
Official API documentation can be found [here](https://any.run/api-documentation/).

## License requirements

This connector is intended for customers with a 'Hunter' or 'Enterprise' subscription plans mainly, since some features provided by the connector are available with the mentioned plans only. Information about subscription plans and features available with them can be found [here](https://app.any.run/plans/).

## Dependencies

This connector comes with some additional python 3 libraries, that it depends on, including:

```
	- aiosignal-1.3.2 (Apache License 2.0, Copyright 2013-2019 Nikolay Kim and Andrew Svetlov)
	- async_timeout-5.0.1 (Apache License 2.0, Copyright 2016-2020 aio-libs collaboration)
	- attrs-25.1.0 (MIT License, Copyright (c) 2015 Hynek Schlawack and the attrs contributors)
	- multidict-6.1.0 (Apache License 2.0, Copyright 2016 Andrew Svetlov and aio-libs contributors)
	- propcache-0.2.1 (Apache License 2.0, Copyright 2016-2021, Andrew Svetlov and aio-libs team)
	- yarl-1.18.3 (Apache License 2.0, Copyright 2016-2021, Andrew Svetlov and aio-libs team)
	- frozenlist-1.5.0 (Apache License 2.0, Copyright 2013-2019 Nikolay Kim and Andrew Svetlov)
	- aiohttp-3.11.12 (Apache License 2.0, Copyright aio-libs contributors)
	- aiofiles-24.1.0
	- aiohappyeyeballs-2.6.1
	- async-timeout-5.0.1
	- anyrun-sdk-1.2.3
```

### Configuration variables

This table lists the configuration variables required to operate ANY.RUN. These variables are specified when configuring a ANY.RUN asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**anyrun_api_key** | required | password | API Key used for API authentication |
**anyrun_timeout** | required | numeric | Number of seconds to wait for a request to timeout |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[get analysis verdict](#action-get-analysis-verdict) - Get the verdict of a specific analysis \
[url reputation](#action-url-reputation) - Get reports of a specific URL analysis \
[file reputation](#action-file-reputation) - Get reports of a specific file analysis by that file's hash \
[domain reputation](#action-domain-reputation) - Get reports of analyses, that involve specific domain \
[ip reputation](#action-ip-reputation) - Get reports of analyses, that involve specific IP \
[get report](#action-get-report) - Get report for a submission \
[get report stix](#action-get-report-stix) - Get report for a submission in STIX format \
[get report misp](#action-get-report-misp) - Get report for a submission in MISP format \
[get report html](#action-get-report-html) - Get report for a submission in HTML format \
[get iocs](#action-get-iocs) - Get list of IoCs for a submission \
[detonate url windows](#action-detonate-url-windows) - Detonate a URL \
[detonate url linux](#action-detonate-url-linux) - Detonate a URL on Linux \
[detonate url android](#action-detonate-url-android) - Detonate a URL on Android \
[detonate file windows](#action-detonate-file-windows) - Detonate a file from Vault \
[detonate file linux](#action-detonate-file-linux) - Detonate a file from Vault \
[detonate file android](#action-detonate-file-android) - Detonate a file from Vault \
[get intelligence](#action-get-intelligence) - Threat Intelligence IoC Lookup \
[delete submission](#action-delete-submission) - Delete a submission \
[download pcap](#action-download-pcap) - Download a pcap file

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get analysis verdict'

Get the verdict of a specific analysis

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | |
action_result.data.verdict | string | | No threats detected Suspicious activity Malicious activity |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |

## action: 'url reputation'

Get reports of a specific URL analysis

Type: **investigate** \
Read only: **True**

This action requests a list of already completed reports of a URL analysis. Option <b>search_in_public_tasks</b> enables search in public submissions, which requires <b>ANY.RUN TI License</b> to work, and is disabled by default. By default, only 100 recent submissions from your own submission history are used for search.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL (Size range: 2-256) | string | `url` |
**search_in_public_tasks** | optional | Option for searching in public tasks (requires TI license) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.url | string | `url` | |
action_result.parameter.search_in_public_tasks | boolean | | |
action_result.data.\*.tasks.\*.uuid | string | `anyrun task id` | 0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.mainObject.name | string | | |
action_result.data.\*.tasks.\*.verdict | string | | No threats detected Suspicious activity Malicious activity |
action_result.data.\*.tasks.\*.related | string | | https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.date | string | | 2024-01-01T00:00:00.000Z |
action_result.data.\*.tasks.\*.file | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 |
action_result.data.\*.tasks.\*.misp | string | | https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp |
action_result.data.\*.tasks.\*.pcap | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap |
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string | `hash` `md5` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string | `hash` `sha1` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string | `hash` `sha256` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |

## action: 'file reputation'

Get reports of a specific file analysis by that file's hash

Type: **investigate** \
Read only: **True**

This action requests a list of already completed reports of a file analysis. Option <b>search_in_public_tasks</b> enables search in public submissions, which requires <b>ANY.RUN TI License</b> to work, and is disabled by default. By default, only 100 recent submissions from your own submission history are used for search.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | File hash ('MD5', 'SHA1', 'SHA256') (Size range: 2-256) | string | `hash` `md5` `sha1` `sha256` |
**search_in_public_tasks** | optional | Option for searching in public tasks (requires TI license) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.hash | string | `hash` `md5` `sha1` `sha256` | |
action_result.parameter.search_in_public_tasks | boolean | | |
action_result.data.\*.tasks.\*.uuid | string | `anyrun task id` | 0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.mainObject.name | string | | |
action_result.data.\*.tasks.\*.verdict | string | | No threats detected Suspicious activity Malicious activity |
action_result.data.\*.tasks.\*.related | string | | https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.date | string | | 2024-01-01T00:00:00.000Z |
action_result.data.\*.tasks.\*.file | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 |
action_result.data.\*.tasks.\*.misp | string | | https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp |
action_result.data.\*.tasks.\*.pcap | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap |
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string | `hash` `md5` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string | `hash` `sha1` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string | `hash` `sha256` | |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'domain reputation'

Get reports of analyses, that involve specific domain

Type: **investigate** \
Read only: **True**

This action requests a list of already completed reports of analyses, where requested domain was involved. This action requires <b>ANY.RUN TI License</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domainname** | required | Domain name (Size range: 2-256) | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domainname | string | `domain` | |
action_result.data.\*.tasks.\*.uuid | string | `anyrun task id` | 0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.mainObject.name | string | | |
action_result.data.\*.tasks.\*.verdict | string | | No threats detected Suspicious activity Malicious activity |
action_result.data.\*.tasks.\*.related | string | | https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.date | string | | 2024-01-01T00:00:00.000Z |
action_result.data.\*.tasks.\*.file | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 |
action_result.data.\*.tasks.\*.misp | string | | https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp |
action_result.data.\*.tasks.\*.pcap | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap |
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string | `hash` `md5` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string | `hash` `sha1` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string | `hash` `sha256` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |

## action: 'ip reputation'

Get reports of analyses, that involve specific IP

Type: **investigate** \
Read only: **True**

This action requests a list of already completed reports of analyses, where requested IP was involved. This action requires <b>ANY.RUN TI License</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP (Size range: 2-256) | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string | `ip` | |
action_result.data.\*.tasks.\*.uuid | string | `anyrun task id` | 0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.mainObject.name | string | | |
action_result.data.\*.tasks.\*.verdict | string | | No threats detected Suspicious activity Malicious activity |
action_result.data.\*.tasks.\*.related | string | | https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.tasks.\*.date | string | | 2024-01-01T00:00:00.000Z |
action_result.data.\*.tasks.\*.file | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 |
action_result.data.\*.tasks.\*.misp | string | | https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp |
action_result.data.\*.tasks.\*.pcap | string | | https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap |
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string | `hash` `md5` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string | `hash` `sha1` | |
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string | `hash` `sha256` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |

## action: 'get report'

Get report for a submission

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | 0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.analysis.permanentUrl | string | | https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.analysis.reports.ioc | string | | https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/ioc/json |
action_result.data.\*.analysis.reports.graph | string | | https://content.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/graph |
action_result.data.\*.analysis.scores.verdict.threatLevelText | string | | No threats detected Suspicious activity Malicious activity |
action_result.data.\*.analysis.scores.verdict.threatLevel | numeric | | 0 1 2 |
action_result.data.\*.analysis.scores.verdict.score | numeric | | 100 |
action_result.data.\*.analysis.scores.specs.knownThreat | string | | false true |
action_result.data.\*.analysis.content.mainObject.type | string | | file download url |
action_result.data.\*.analysis.content.mainObject.url | string | | |
action_result.data.\*.analysis.content.mainObject.filename | string | | |
action_result.data.\*.analysis.content.mainObject.info.file | string | | |
action_result.data.\*.analysis.content.mainObject.info.mime | string | | |
action_result.data.\*.analysis.content.mainObject.hashes.sha256 | string | `hash` `sha256` | |
action_result.data.\*.analysis.content.mainObject.hashes.sha1 | string | `hash` `sha1` | |
action_result.data.\*.analysis.content.mainObject.hashes.md5 | string | `hash` `md5` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |

## action: 'get report stix'

Get report for a submission in STIX format

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | |
action_result.data.type | string | | bundle |
action_result.data.id | string | | |
action_result.data.objects.\*.id | string | | |
action_result.data.objects.\*.name | string | | |
action_result.data.objects.\*.type | string | | |
action_result.summary | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get report misp'

Get report for a submission in MISP format

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | |
action_result.data.Event.uuid | string | | |
action_result.data.Event.distribution | numeric | | |
action_result.data.Event.analysis | numeric | | |
action_result.data.Event.threat_level_id | numeric | | |
action_result.data.Event.info | string | | |
action_result.data.Event.timestamp | string | | |
action_result.data.Event.date | string | | |
action_result.data.Event.Attribute.\*.category | string | | |
action_result.data.Event.Attribute.\*.type | string | | |
action_result.data.Event.Attribute.\*.value | string | | |
action_result.data.Event.Attribute.\*.distribution | numeric | | |
action_result.data.Event.Orgc.uuid | string | | |
action_result.data.Event.Orgc.name | string | | |
action_result.summary | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get report html'

Get report for a submission in HTML format

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | |
action_result.data.html | string | | |
action_result.summary | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'get iocs'

Get list of IoCs for a submission

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | 0cf223f2-530e-4a50-b68f-563045268648 |
action_result.data.\*.ioc.\*.ioc | string | | |
action_result.data.\*.ioc.\*.type | string | | md5 sha1 sha256 domain ip url |
action_result.data.\*.ioc.\*.category | string | | |
action_result.data.\*.ioc.\*.reputation | numeric | | 0 1 2 |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |

## action: 'detonate url windows'

Detonate a URL

Type: **investigate** \
Read only: **True**

This action requires a <b>URL</b> for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**obj_url** | required | URL to detonate (Size range: 5-512) | string | `url` |
**opt_timeout** | optional | Timeout (Default: 60) | numeric | |
**env_bitness** | optional | Bitness of the operation system (Default: 64) | numeric | |
**env_locale** | optional | Operation system's language (Default: en-US) | string | |
**env_type** | optional | Type of the operation system (Default: complete) | string | |
**env_version** | optional | Version of the operation system (Default: 10) | string | |
**obj_ext_browser** | optional | Browser to use (Default: Microsoft Edge) | string | |
**obj_ext_extension** | optional | Extension to use (Default: True) | boolean | |
**opt_automated_interactivity** | optional | Automated interactivity (Default: True) | boolean | |
**opt_kernel_heavyevasion** | optional | Kernel heavy evasion (Default: False) | boolean | |
**opt_network_connect** | optional | Network connection state (Default: True) | boolean | |
**opt_network_fakenet** | optional | FakeNet feature status (Default: False) | boolean | |
**opt_network_geo** | optional | Geo location option (Default: fastest) | string | |
**opt_network_mitm** | optional | HTTPS MITM proxy option (Default: False) | boolean | |
**opt_network_residential_proxy** | optional | Residential proxy using (Default: False) | boolean | |
**opt_network_residential_proxy_geo** | optional | Residential proxy geo location option (Default: fastest) | string | |
**opt_network_tor** | optional | TOR using (Default: False) | boolean | |
**opt_privacy_type** | optional | Privacy type (Default: bylink) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.obj_url | string | `url` | |
action_result.data.\*.taskid | string | `anyrun task id` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |
action_result.parameter.opt_timeout | numeric | | |
action_result.parameter.env_bitness | numeric | | |
action_result.parameter.env_locale | string | | |
action_result.parameter.env_type | string | | |
action_result.parameter.env_version | string | | |
action_result.parameter.obj_ext_browser | string | | |
action_result.parameter.obj_ext_extension | boolean | | |
action_result.parameter.opt_automated_interactivity | boolean | | |
action_result.parameter.opt_kernel_heavyevasion | boolean | | |
action_result.parameter.opt_network_connect | boolean | | |
action_result.parameter.opt_network_fakenet | boolean | | |
action_result.parameter.opt_network_geo | string | | |
action_result.parameter.opt_network_mitm | boolean | | |
action_result.parameter.opt_network_residential_proxy | boolean | | |
action_result.parameter.opt_network_residential_proxy_geo | string | | |
action_result.parameter.opt_network_tor | boolean | | |
action_result.parameter.opt_privacy_type | string | | |

## action: 'detonate url linux'

Detonate a URL on Linux

Type: **investigate** \
Read only: **True**

This action requires a <b>URL</b> for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**obj_url** | required | URL to detonate (Size range: 5-512) | string | `url` |
**opt_timeout** | optional | Timeout (Default: 60) | numeric | |
**env_os** | optional | Operation System (Default: ubuntu) | string | |
**obj_ext_browser** | optional | Browser to use (Default: Google Chrome) | string | |
**obj_ext_extension** | optional | Extension to use (Default: True) | boolean | |
**opt_automated_interactivity** | optional | Automated interactivity (Default: True) | boolean | |
**opt_kernel_heavyevasion** | optional | Kernel heavy evasion (Default: False) | boolean | |
**opt_network_connect** | optional | Network connection state (Default: True) | boolean | |
**opt_network_fakenet** | optional | FakeNet feature status (Default: False) | boolean | |
**opt_network_geo** | optional | Geo location option (Default: fastest) | string | |
**opt_network_mitm** | optional | HTTPS MITM proxy option (Default: False) | boolean | |
**opt_network_residential_proxy** | optional | Residential proxy using (Default: False) | boolean | |
**opt_network_residential_proxy_geo** | optional | Residential proxy geo location option (Default: fastest) | string | |
**opt_network_tor** | optional | TOR using (Default: False) | boolean | |
**opt_privacy_type** | optional | Privacy type (Default: bylink) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.obj_url | string | `url` | |
action_result.data.\*.taskid | string | `anyrun task id` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |
action_result.parameter.opt_timeout | numeric | | |
action_result.parameter.env_os | string | | |
action_result.parameter.obj_ext_browser | string | | |
action_result.parameter.obj_ext_extension | boolean | | |
action_result.parameter.opt_automated_interactivity | boolean | | |
action_result.parameter.opt_kernel_heavyevasion | boolean | | |
action_result.parameter.opt_network_connect | boolean | | |
action_result.parameter.opt_network_fakenet | boolean | | |
action_result.parameter.opt_network_geo | string | | |
action_result.parameter.opt_network_mitm | boolean | | |
action_result.parameter.opt_network_residential_proxy | boolean | | |
action_result.parameter.opt_network_residential_proxy_geo | string | | |
action_result.parameter.opt_network_tor | boolean | | |
action_result.parameter.opt_privacy_type | string | | |

## action: 'detonate url android'

Detonate a URL on Android

Type: **investigate** \
Read only: **True**

This action requires a <b>URL</b> for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**obj_url** | required | URL to detonate (Size range: 5-512) | string | `url` |
**env_locale** | optional | Operation system's language (Default: en-US) | string | |
**opt_timeout** | optional | Timeout (Default: 60) | numeric | |
**obj_ext_browser** | optional | Browser to use (Default: Google Chrome) | string | |
**opt_automated_interactivity** | optional | Automated interactivity (Default: True) | boolean | |
**opt_network_connect** | optional | Network connection state (Default: True) | boolean | |
**opt_network_fakenet** | optional | FakeNet feature status (Default: False) | boolean | |
**opt_network_geo** | optional | Geo location option (Default: fastest) | string | |
**opt_network_mitm** | optional | HTTPS MITM proxy option (Default: False) | boolean | |
**opt_network_residential_proxy** | optional | Residential proxy using (Default: False) | boolean | |
**opt_network_residential_proxy_geo** | optional | Residential proxy geo location option (Default: fastest) | string | |
**opt_network_tor** | optional | TOR using (Default: False) | boolean | |
**opt_privacy_type** | optional | Privacy type (Default: bylink) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.obj_url | string | `url` | |
action_result.data.\*.taskid | string | `anyrun task id` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |
action_result.parameter.env_locale | string | | |
action_result.parameter.opt_timeout | numeric | | |
action_result.parameter.obj_ext_browser | string | | |
action_result.parameter.opt_automated_interactivity | boolean | | |
action_result.parameter.opt_network_connect | boolean | | |
action_result.parameter.opt_network_fakenet | boolean | | |
action_result.parameter.opt_network_geo | string | | |
action_result.parameter.opt_network_mitm | boolean | | |
action_result.parameter.opt_network_residential_proxy | boolean | | |
action_result.parameter.opt_network_residential_proxy_geo | string | | |
action_result.parameter.opt_network_tor | boolean | | |
action_result.parameter.opt_privacy_type | string | | |

## action: 'detonate file windows'

Detonate a file from Vault

Type: **investigate** \
Read only: **True**

This action requires a <b>vault ID</b> of a file for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of a file to detonate | string | `vault id` |
**opt_timeout** | optional | Timeout (Default: 60) | numeric | |
**auto_confirm_uac** | optional | Auto confirm UAC (Default: True) | boolean | |
**env_bitness** | optional | Bitness of the operation system (Default: 64) | numeric | |
**env_locale** | optional | Operation system's language (Default: en-US) | string | |
**env_type** | optional | Type of the operation system (Default: complete) | string | |
**env_version** | optional | Version of the operation system (Default: 10) | string | |
**obj_force_elevation** | optional | Force elevation (Default: False) | boolean | |
**obj_ext_startfolder** | optional | Start folder (Default: desktop) | string | |
**obj_ext_cmd** | optional | Command to execute (Default: <empty>) | string | |
**obj_ext_extension** | optional | Extension to use (Default: True) | boolean | |
**opt_automated_interactivity** | optional | Automated interactivity (Default: True) | boolean | |
**opt_kernel_heavyevasion** | optional | Kernel heavy evasion (Default: False) | boolean | |
**opt_network_connect** | optional | Network connection state (Default: True) | boolean | |
**opt_network_fakenet** | optional | FakeNet feature status (Default: False) | boolean | |
**opt_network_geo** | optional | Geo location option (Default: fastest) | string | |
**opt_network_mitm** | optional | HTTPS MITM proxy option (Default: False) | boolean | |
**opt_network_residential_proxy** | optional | Residential proxy using (Default: False) | boolean | |
**opt_network_residential_proxy_geo** | optional | Residential proxy geo location option (Default: fastest) | string | |
**opt_network_tor** | optional | TOR using (Default: False) | boolean | |
**opt_privacy_type** | optional | Privacy type (Default: bylink) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.vault_id | string | `vault id` | |
action_result.data.\*.taskid | string | `anyrun task id` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |
action_result.parameter.opt_timeout | numeric | | |
action_result.parameter.auto_confirm_uac | boolean | | |
action_result.parameter.env_bitness | numeric | | |
action_result.parameter.env_locale | string | | |
action_result.parameter.env_type | string | | |
action_result.parameter.env_version | string | | |
action_result.parameter.obj_force_elevation | boolean | | |
action_result.parameter.obj_ext_startfolder | string | | |
action_result.parameter.obj_ext_cmd | string | | |
action_result.parameter.obj_ext_extension | boolean | | |
action_result.parameter.opt_automated_interactivity | boolean | | |
action_result.parameter.opt_kernel_heavyevasion | boolean | | |
action_result.parameter.opt_network_connect | boolean | | |
action_result.parameter.opt_network_fakenet | boolean | | |
action_result.parameter.opt_network_geo | string | | |
action_result.parameter.opt_network_mitm | boolean | | |
action_result.parameter.opt_network_residential_proxy | boolean | | |
action_result.parameter.opt_network_residential_proxy_geo | string | | |
action_result.parameter.opt_network_tor | boolean | | |
action_result.parameter.opt_privacy_type | string | | |

## action: 'detonate file linux'

Detonate a file from Vault

Type: **investigate** \
Read only: **True**

This action requires a <b>vault ID</b> of a file for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of a file to detonate | string | `vault id` |
**opt_timeout** | optional | Timeout (Default: 60) | numeric | |
**env_locale** | optional | Operation system's language (Default: en-US) | string | |
**env_os** | optional | Operation System (Default: ubuntu) | string | |
**obj_ext_startfolder** | optional | Start folder (Default: temp) | string | |
**obj_ext_cmd** | optional | Command to execute (Default: <empty>) | string | |
**obj_ext_extension** | optional | Extension to use (Default: True) | boolean | |
**opt_automated_interactivity** | optional | Automated interactivity (Default: True) | boolean | |
**opt_kernel_heavyevasion** | optional | Kernel heavy evasion (Default: False) | boolean | |
**opt_network_connect** | optional | Network connection state (Default: True) | boolean | |
**opt_network_fakenet** | optional | FakeNet feature status (Default: False) | boolean | |
**opt_network_geo** | optional | Geo location option (Default: fastest) | string | |
**opt_network_mitm** | optional | HTTPS MITM proxy option (Default: False) | boolean | |
**opt_network_residential_proxy** | optional | Residential proxy using (Default: False) | boolean | |
**opt_network_residential_proxy_geo** | optional | Residential proxy geo location option (Default: fastest) | string | |
**opt_network_tor** | optional | TOR using (Default: False) | boolean | |
**opt_privacy_type** | optional | Privacy type (Default: bylink) | string | |
**run_as_root** | optional | Run as root (Default: False) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.vault_id | string | `vault id` | |
action_result.data.\*.taskid | string | `anyrun task id` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |
action_result.parameter.opt_timeout | numeric | | |
action_result.parameter.env_locale | string | | |
action_result.parameter.env_os | string | | |
action_result.parameter.obj_ext_startfolder | string | | |
action_result.parameter.obj_ext_cmd | string | | |
action_result.parameter.obj_ext_extension | boolean | | |
action_result.parameter.opt_automated_interactivity | boolean | | |
action_result.parameter.opt_kernel_heavyevasion | boolean | | |
action_result.parameter.opt_network_connect | boolean | | |
action_result.parameter.opt_network_fakenet | boolean | | |
action_result.parameter.opt_network_geo | string | | |
action_result.parameter.opt_network_mitm | boolean | | |
action_result.parameter.opt_network_residential_proxy | boolean | | |
action_result.parameter.opt_network_residential_proxy_geo | string | | |
action_result.parameter.opt_network_tor | boolean | | |
action_result.parameter.opt_privacy_type | string | | |
action_result.parameter.run_as_root | boolean | | |

## action: 'detonate file android'

Detonate a file from Vault

Type: **investigate** \
Read only: **True**

This action requires a <b>vault ID</b> of a file for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of a file to detonate | string | `vault id` |
**opt_timeout** | optional | Timeout (Default: 60) | numeric | |
**env_locale** | optional | Operation system's language (Default: en-US) | string | |
**obj_ext_cmd** | optional | Command to execute (Default: <empty>) | string | |
**opt_automated_interactivity** | optional | Automated interactivity (Default: True) | boolean | |
**opt_network_connect** | optional | Network connection state (Default: True) | boolean | |
**opt_network_fakenet** | optional | FakeNet feature status (Default: False) | boolean | |
**opt_network_geo** | optional | Geo location option (Default: fastest) | string | |
**opt_network_mitm** | optional | HTTPS MITM proxy option (Default: False) | boolean | |
**opt_network_residential_proxy** | optional | Residential proxy using (Default: False) | boolean | |
**opt_network_residential_proxy_geo** | optional | Residential proxy geo location option (Default: fastest) | string | |
**opt_network_tor** | optional | TOR using (Default: False) | boolean | |
**opt_privacy_type** | optional | Privacy type (Default: bylink) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.vault_id | string | `vault id` | |
action_result.data.\*.taskid | string | `anyrun task id` | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.summary | string | | |
action_result.parameter.opt_timeout | numeric | | |
action_result.parameter.env_locale | string | | |
action_result.parameter.obj_ext_cmd | string | | |
action_result.parameter.opt_automated_interactivity | boolean | | |
action_result.parameter.opt_network_connect | boolean | | |
action_result.parameter.opt_network_fakenet | boolean | | |
action_result.parameter.opt_network_geo | string | | |
action_result.parameter.opt_network_mitm | boolean | | |
action_result.parameter.opt_network_residential_proxy | boolean | | |
action_result.parameter.opt_network_residential_proxy_geo | string | | |
action_result.parameter.opt_network_tor | boolean | | |
action_result.parameter.opt_privacy_type | string | | |

## action: 'get intelligence'

Threat Intelligence IoC Lookup

Type: **investigate** \
Read only: **True**

Perform investigative actions by using the ANY.RUN Threat Intelligence Portal API method. This action requires <b>ANY.RUN TI License</b>. For more information about available parameters refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sha256** | optional | Sha256 (Size range: 2-256) | string | `hash` `sha256` |
**sha1** | optional | Sha1 (Size range: 2-256) | string | `hash` `sha1` |
**md5** | optional | MD5 (Size range: 2-256) | string | `hash` `md5` |
**threat_name** | optional | Name of threat (Size range: 2-256) | string | |
**threat_level** | optional | Threat level (Default: <empty>) | string | |
**task_type** | optional | Task run type (Default: <empty>) | string | |
**submission_country** | optional | Submission country (Size range: 2-256) | string | |
**os** | optional | Operation system (Default: <empty> - not used) | string | |
**os_software_set** | optional | Operation system software (Default: <empty> - not used) | string | |
**os_bit_version** | optional | Operation system bitness (Default: <empty> - not used) | numeric | |
**registry_key** | optional | Registry key (Size range: 2-256) | string | |
**registry_name** | optional | Registry name (Size range: 2-256) | string | |
**registry_value** | optional | Registry value (Size range: 2-256) | string | |
**module_image_path** | optional | Module image path (Size range: 2-256) | string | `file path` |
**rule_threat_level** | optional | Rule threat level (Default: <empty> - not used) | string | |
**rule_name** | optional | Rule name (Size range: 2-256) | string | |
**mitre** | optional | MITRE (Size range: 2-256) | string | |
**image_path** | optional | Process image path (Size range: 2-256) | string | `file path` |
**command_line** | optional | Command line (Size range: 2-256) | string | `process name` |
**injected_flag** | optional | Injected flag (Default: <empty> - not used) | string | |
**destination_ip** | optional | Destination ip (Size range: 2-256) | string | `ip` |
**destination_port** | optional | Destination port (Default: <empty> - not used) (Size range: 1-65535) | numeric | `port` |
**destination_ip_asn** | optional | Destination IPASN (Size range: 2-256) | string | |
**destination_ip_geo** | optional | Destination IP Geo (Size range: 2-256) | string | |
**domain_name** | optional | Domain name (Size range: 2-256) | string | `domain` |
**file_path** | optional | File path (Size range: 2-256) | string | `file path` |
**suricata_class** | optional | Suricata class (Default: <empty> - not used) | string | |
**suricata_message** | optional | Suricata message (Size range: 2-256) | string | |
**suricata_threat_level** | optional | Suricata threat level (Default: <empty> - not used) | string | |
**suricata_id** | optional | Suricata ID (Size range: 2-256) | string | |
**url** | optional | URL (Size range: 2-256) | string | `url` |
**http_request_content_type** | optional | HTTP request content type (Size range: 2-256) | string | |
**http_response_content_type** | optional | HTTP response content type (Size range: 2-256) | string | |
**http_request_file_type** | optional | HTTP request file type (Size range: 2-256) | string | |
**http_response_file_type** | optional | HTTP response file type (Size range: 2-256) | string | |
**file_event_path** | optional | File Event Path (Size range: 2-256) | string | |
**file_extension** | optional | File Extension (Size range: 2-256) | string | |
**sync_object_name** | optional | Sync Object Name (Size range: 2-256) | string | |
**sync_object_type** | optional | Sync Object Type (Size range: 2-256) | string | |
**sync_object_operation** | optional | Sync Object Operation (Size range: 2-256) | string | |
**ja3** | optional | JA3 (Size range: 2-256) | string | |
**ja3s** | optional | JA3S (Size range: 2-256) | string | |
**jarm** | optional | JARM (Size range: 2-256) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.sha256 | string | `hash` `sha256` | |
action_result.parameter.sha1 | string | `hash` `sha1` | |
action_result.parameter.md5 | string | `hash` `md5` | |
action_result.parameter.os | string | | |
action_result.parameter.mitre | string | | |
action_result.parameter.url | string | `url` | |
action_result.parameter.ja3 | string | | |
action_result.parameter.ja3s | string | | |
action_result.parameter.jarm | string | | |
action_result.data.\*.summary.threatLevel | string | | |
action_result.data.\*.summary.detectedType | string | | |
action_result.data.\*.summary.lastSeen | string | | |
action_result.summary.\*.Type | string | | |
action_result.summary.\*.Count | numeric | | |
action_result.summary.\*.str | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.threat_name | string | | |
action_result.parameter.threat_level | string | | |
action_result.parameter.task_type | string | | |
action_result.parameter.submission_country | string | | |
action_result.parameter.os_software_set | string | | |
action_result.parameter.os_bit_version | numeric | | |
action_result.parameter.registry_key | string | | |
action_result.parameter.registry_name | string | | |
action_result.parameter.registry_value | string | | |
action_result.parameter.module_image_path | string | `file path` | |
action_result.parameter.rule_threat_level | string | | |
action_result.parameter.rule_name | string | | |
action_result.parameter.image_path | string | `file path` | |
action_result.parameter.command_line | string | `process name` | |
action_result.parameter.injected_flag | string | | |
action_result.parameter.destination_ip | string | `ip` | |
action_result.parameter.destination_port | numeric | `port` | |
action_result.parameter.destination_ip_asn | string | | |
action_result.parameter.destination_ip_geo | string | | |
action_result.parameter.domain_name | string | `domain` | |
action_result.parameter.file_path | string | `file path` | |
action_result.parameter.suricata_class | string | | |
action_result.parameter.suricata_message | string | | |
action_result.parameter.suricata_threat_level | string | | |
action_result.parameter.suricata_id | string | | |
action_result.parameter.http_request_content_type | string | | |
action_result.parameter.http_response_content_type | string | | |
action_result.parameter.http_request_file_type | string | | |
action_result.parameter.http_response_file_type | string | | |
action_result.parameter.file_event_path | string | | |
action_result.parameter.file_extension | string | | |
action_result.parameter.sync_object_name | string | | |
action_result.parameter.sync_object_type | string | | |
action_result.parameter.sync_object_operation | string | | |

## action: 'delete submission'

Delete a submission

Type: **investigate** \
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | |
action_result.data.info | string | | |
action_result.summary | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

## action: 'download pcap'

Download a pcap file

Type: **investigate** \
Read only: **True**

This action requires a task <b>TaskID</b>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**taskid** | required | ANY.RUN task UUID | string | `anyrun task id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.taskid | string | `anyrun task id` | |
action_result.data.vault_id | string | | |
action_result.info | string | | |
action_result.summary | string | | |
action_result.status | string | | success failed |
action_result.message | string | | |
summary.total_objects_successful | numeric | | |
summary.total_objects | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
