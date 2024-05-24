[comment]: # "Auto-generated SOAR connector documentation"
# ANY.RUN

Publisher: ANYRUN FZCO  
Connector Version: 1.0.0  
Product Vendor: ANYRUN FZCO  
Product Name: ANY.RUN  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.0.355  

This app enables you to detonate files and URLs, and perform investigative actions, using the ANY.RUN interactive online malware sandbox service, thereby giving you automated analysis and advanced threat detection through an agentless sandbox.

# Splunk> Phantom

Welcome to the open-source repository for Splunk> Phantom's any.run App.

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) if you are interested in contributing, raising issues, or learning more about open-source Phantom apps.

## Legal and License

This Phantom App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ANY.RUN asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**anyrun_server** |  required  | string | ANY.RUN base URL (e.g. https://api.any.run)
**anyrun_api_key** |  required  | password | API Key used for API authentication
**anyrun_timeout** |  required  | numeric | Number of seconds to wait for a request to timeout

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[ANYRUN SBTI Get URL Reputation](#action-anyrun-sbti-get-url-reputation) - Get reports of a specific URL analysis  
[ANYRUN SBTI Get File Reputation](#action-anyrun-sbti-get-file-reputation) - Get reports of a specific file analysis by that file's hash  
[ANYRUN TI Get Domain Reputation](#action-anyrun-ti-get-domain-reputation) - Get reports of analyses, that involve specific domain  
[ANYRUN TI Get IP Reputation](#action-anyrun-ti-get-ip-reputation) - Get reports of analyses, that involve specific IP  
[ANYRUN SB Get Report](#action-anyrun-sb-get-report) - Get report for a submission  
[ANYRUN SB Get IoCs](#action-anyrun-sb-get-iocs) - Get list of IoCs for a submission  
[ANYRUN SB Detonate URL](#action-anyrun-sb-detonate-url) - Detonate a URL  
[ANYRUN SB Detonate File](#action-anyrun-sb-detonate-file) - Detonate a file  
[ANYRUN TI Get Intelligence](#action-anyrun-ti-get-intelligence) - Threat Intelligence IoC Lookup  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'ANYRUN SBTI Get URL Reputation'
Get reports of a specific URL analysis

Type: **generic**  
Read only: **True**

This action requests a list of already completed reports of a URL analysis. Option <b>search_in_public_tasks</b> enables search in public submissions, which requires <b>ANY.RUN TI License</b> to work, and is disabled by default. By default, only 100 recent submissions from your own submission history are used for search.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**URL** |  required  | URL (Size range: 2-256) | string |  `url` 
**search_in_public_tasks** |  optional  | Option for searching in public tasks (requires TI license) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.URL | string |  `url`  |  
action_result.parameter.search_in_public_tasks | boolean |  |  
action_result.data.\*.tasks.\*.uuid | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.mainObject.name | string |  |  
action_result.data.\*.tasks.\*.verdict | string |  |   No threats detected  Suspicious activity  Malicious activity 
action_result.data.\*.tasks.\*.related | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.date | string |  |   2024-01-01T00:00:00.000Z 
action_result.data.\*.tasks.\*.file | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 
action_result.data.\*.tasks.\*.misp | string |  |   https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp 
action_result.data.\*.tasks.\*.pcap | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap 
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string |  `hash`  `md5`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string |  `hash`  `sha256`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN SBTI Get File Reputation'
Get reports of a specific file analysis by that file's hash

Type: **generic**  
Read only: **True**

This action requests a list of already completed reports of a file analysis. Option <b>search_in_public_tasks</b> enables search in public submissions, which requires <b>ANY.RUN TI License</b> to work, and is disabled by default. By default, only 100 recent submissions from your own submission history are used for search.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Hash** |  required  | File hash ('MD5', 'SHA1', 'SHA256') (Size range: 2-256) | string |  `hash`  `md5`  `sha1`  `sha256` 
**search_in_public_tasks** |  optional  | Option for searching in public tasks (requires TI license) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Hash | string |  `hash`  `md5`  `sha1`  `sha256`  |  
action_result.parameter.search_in_public_tasks | boolean |  |  
action_result.data.\*.tasks.\*.uuid | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.mainObject.name | string |  |  
action_result.data.\*.tasks.\*.verdict | string |  |   No threats detected  Suspicious activity  Malicious activity 
action_result.data.\*.tasks.\*.related | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.date | string |  |   2024-01-01T00:00:00.000Z 
action_result.data.\*.tasks.\*.file | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 
action_result.data.\*.tasks.\*.misp | string |  |   https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp 
action_result.data.\*.tasks.\*.pcap | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap 
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string |  `hash`  `md5`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string |  `hash`  `sha256`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN TI Get Domain Reputation'
Get reports of analyses, that involve specific domain

Type: **generic**  
Read only: **True**

This action requests a list of already completed reports of analyses, where requested domain was involved. This action requires <b>ANY.RUN TI License</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**DomainName** |  required  | Domain name (Size range: 2-256) | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.DomainName | string |  `domain`  |  
action_result.data.\*.tasks.\*.uuid | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.mainObject.name | string |  |  
action_result.data.\*.tasks.\*.verdict | string |  |   No threats detected  Suspicious activity  Malicious activity 
action_result.data.\*.tasks.\*.related | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.date | string |  |   2024-01-01T00:00:00.000Z 
action_result.data.\*.tasks.\*.file | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 
action_result.data.\*.tasks.\*.misp | string |  |   https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp 
action_result.data.\*.tasks.\*.pcap | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap 
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string |  `hash`  `md5`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string |  `hash`  `sha256`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN TI Get IP Reputation'
Get reports of analyses, that involve specific IP

Type: **generic**  
Read only: **True**

This action requests a list of already completed reports of analyses, where requested IP was involved. This action requires <b>ANY.RUN TI License</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**IP** |  required  | IP (Size range: 2-256) | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.IP | string |  `ip`  |  
action_result.data.\*.tasks.\*.uuid | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.mainObject.name | string |  |  
action_result.data.\*.tasks.\*.verdict | string |  |   No threats detected  Suspicious activity  Malicious activity 
action_result.data.\*.tasks.\*.related | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.tasks.\*.date | string |  |   2024-01-01T00:00:00.000Z 
action_result.data.\*.tasks.\*.file | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/files/65c5ff68-b453-415c-abf9-0023ea44dd89 
action_result.data.\*.tasks.\*.misp | string |  |   https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/summary/misp 
action_result.data.\*.tasks.\*.pcap | string |  |   https://content.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648/download/pcap 
action_result.data.\*.tasks.\*.mainObject.hashes.md5 | string |  `hash`  `md5`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.tasks.\*.mainObject.hashes.sha256 | string |  `hash`  `sha256`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN SB Get Report'
Get report for a submission

Type: **investigate**  
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**TaskID** |  required  | ANY.RUN task UUID | string |  `anyrun task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.TaskID | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.analysis.permanentUrl | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.analysis.reports.ioc | string |  |   https://api.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/ioc/json 
action_result.data.\*.analysis.reports.graph | string |  |   https://content.any.run/report/0cf223f2-530e-4a50-b68f-563045268648/graph 
action_result.data.\*.analysis.scores.verdict.threatLevelText | string |  |   No threats detected  Suspicious activity  Malicious activity 
action_result.data.\*.analysis.scores.verdict.threatLevel | numeric |  |   0  1  2 
action_result.data.\*.analysis.scores.verdict.score | numeric |  |   100 
action_result.data.\*.analysis.scores.specs.knownThreat | string |  |   false  true 
action_result.data.\*.analysis.content.mainObject.type | string |  |   file  download  url 
action_result.data.\*.analysis.content.mainObject.url | string |  |  
action_result.data.\*.analysis.content.mainObject.filename | string |  |  
action_result.data.\*.analysis.content.mainObject.info.file | string |  |  
action_result.data.\*.analysis.content.mainObject.info.mime | string |  |  
action_result.data.\*.analysis.content.mainObject.hashes.sha256 | string |  `hash`  `sha256`  |  
action_result.data.\*.analysis.content.mainObject.hashes.sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.analysis.content.mainObject.hashes.md5 | string |  `hash`  `md5`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN SB Get IoCs'
Get list of IoCs for a submission

Type: **investigate**  
Read only: **True**

This action requires a submission <b>TaskID</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**TaskID** |  required  | ANY.RUN task UUID | string |  `anyrun task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.TaskID | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.ioc.\*.ioc | string |  |  
action_result.data.\*.ioc.\*.type | string |  |   md5  sha1  sha256  domain  ip  url 
action_result.data.\*.ioc.\*.category | string |  |  
action_result.data.\*.ioc.\*.reputation | numeric |  |   0  1  2 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN SB Detonate URL'
Detonate a URL

Type: **investigate**  
Read only: **True**

This action requires a <b>URL</b> for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**obj_url** |  required  | URL to detonate (Size range: 5-512) | string |  `url` 
**obj_type** |  optional  | Type of new task (Default: url) | string | 
**os** |  optional  | Operation System (Default: Windows10x64_complete) | string | 
**env_locale** |  optional  | Operation system's language (Default: en-US) | string | 
**opt_network_connect** |  optional  | Network connection state | boolean | 
**opt_network_fakenet** |  optional  | FakeNet feature status | boolean | 
**opt_network_tor** |  optional  | TOR using | boolean | 
**opt_network_geo** |  optional  | Geo location option (Default: fastest) | string | 
**opt_network_mitm** |  optional  | HTTPS MITM proxy option | boolean | 
**opt_network_residential_proxy** |  optional  | Residential proxy using | boolean | 
**opt_network_residential_proxy_geo** |  optional  | Residential proxy geo location option (Default: fastest) | string | 
**opt_kernel_heavyevasion** |  optional  | Heavy evasion option | boolean | 
**opt_privacy_type** |  optional  | Privacy settings (Default: bylink) | string | 
**opt_timeout** |  optional  | Timeout option (seconds) (Default: 60) (Size range: 10-1200) | numeric | 
**opt_automated_interactivity** |  optional  | Automated Interactivity (ML) option | boolean | 
**obj_ext_startfolder** |  optional  | Start object from (Default: temp) | string | 
**obj_ext_cmd** |  optional  | Optional command line (Size range: 2-256) | string | 
**obj_ext_browser** |  optional  | Browser name (Default: Google Chrome) | string | 
**obj_ext_useragent** |  optional  | User agent (Size range: 2-256) | string | 
**obj_ext_extension** |  optional  | Change extension to valid | boolean | 
**opt_privacy_hidesource** |  optional  | Option for hiding of source URL | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.obj_url | string |  `url`  |  
action_result.parameter.obj_type | string |  |   url  download 
action_result.parameter.os | string |  |  
action_result.parameter.env_locale | string |  |  
action_result.parameter.opt_network_connect | boolean |  |  
action_result.parameter.opt_network_fakenet | boolean |  |  
action_result.parameter.opt_network_tor | boolean |  |  
action_result.parameter.opt_network_geo | string |  |  
action_result.parameter.opt_network_mitm | boolean |  |  
action_result.parameter.opt_network_residential_proxy | boolean |  |  
action_result.parameter.opt_network_residential_proxy_geo | string |  |  
action_result.parameter.opt_kernel_heavyevasion | boolean |  |  
action_result.parameter.opt_privacy_type | string |  |  
action_result.parameter.opt_timeout | numeric |  |  
action_result.parameter.opt_automated_interactivity | boolean |  |  
action_result.parameter.obj_ext_startfolder | string |  |  
action_result.parameter.obj_ext_cmd | string |  |  
action_result.parameter.obj_ext_browser | string |  |  
action_result.parameter.obj_ext_useragent | string |  |  
action_result.parameter.obj_ext_elevateprompt | boolean |  |  
action_result.parameter.obj_ext_extension | boolean |  |  
action_result.parameter.opt_privacy_hidesource | boolean |  |  
action_result.data.\*.taskid | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.permanentUrl | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN SB Detonate File'
Detonate a file

Type: **investigate**  
Read only: **True**

This action requires a <b>vauld ID</b> of a file for ANY.RUN service to analyse. All other parameters are optional - for more information about them refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** |  required  | Vault ID of a file to detonate | string |  `vault id` 
**os** |  optional  | Operation System (Default: Windows10x64_complete) | string | 
**env_locale** |  optional  | Operation system's language (Default: en-US) | string | 
**opt_network_connect** |  optional  | Network connection state | boolean | 
**opt_network_fakenet** |  optional  | FakeNet feature status | boolean | 
**opt_network_tor** |  optional  | TOR using | boolean | 
**opt_network_geo** |  optional  | Geo location option (Default: fastest) | string | 
**opt_network_mitm** |  optional  | HTTPS MITM proxy option | boolean | 
**opt_network_residential_proxy** |  optional  | Residential proxy using | boolean | 
**opt_network_residential_proxy_geo** |  optional  | Residential proxy geo location option (Default: fastest) | string | 
**opt_kernel_heavyevasion** |  optional  | Heavy evasion option | boolean | 
**opt_privacy_type** |  optional  | Privacy settings (Default: bylink) | string | 
**opt_timeout** |  optional  | Timeout option (seconds) (Default: 60) (Size range: 10-660) | numeric | 
**opt_automated_interactivity** |  optional  | Automated Interactivity (ML) option | boolean | 
**obj_ext_startfolder** |  optional  | Start object from (Default: temp) | string | 
**obj_ext_cmd** |  optional  | Optional command line (Size range: 2-256) | string | 
**obj_ext_elevateprompt** |  optional  | Encounter UAC prompts | boolean | 
**auto_confirm_uac** |  optional  | Auto confirm Windows UAC requests. Not applicable for Linux , use run_as_root instead | boolean | 
**run_as_root** |  optional  | Run file with superuser privileges. Not applicable for Windows, use auto_confirm_uac instead. Used only for file type | boolean | 
**obj_ext_extension** |  optional  | Change extension to valid | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.vault_id | string |  `vault id`  |  
action_result.parameter.os | string |  |  
action_result.parameter.env_locale | string |  |  
action_result.parameter.opt_network_connect | boolean |  |  
action_result.parameter.opt_network_fakenet | boolean |  |  
action_result.parameter.opt_network_tor | boolean |  |  
action_result.parameter.opt_network_geo | string |  |  
action_result.parameter.opt_network_mitm | boolean |  |  
action_result.parameter.opt_network_residential_proxy | boolean |  |  
action_result.parameter.opt_network_residential_proxy_geo | string |  |  
action_result.parameter.opt_kernel_heavyevasion | boolean |  |  
action_result.parameter.opt_privacy_type | string |  |  
action_result.parameter.opt_timeout | numeric |  |  
action_result.parameter.opt_automated_interactivity | boolean |  |  
action_result.parameter.obj_ext_startfolder | string |  |  
action_result.parameter.obj_ext_cmd | string |  |  
action_result.parameter.obj_ext_elevateprompt | boolean |  |  
action_result.parameter.auto_confirm_uac | boolean |  |  
action_result.parameter.run_as_root | boolean |  |  
action_result.parameter.obj_ext_extension | boolean |  |  
action_result.data.\*.taskid | string |  `anyrun task id`  |   0cf223f2-530e-4a50-b68f-563045268648 
action_result.data.\*.permanentUrl | string |  |   https://app.any.run/tasks/0cf223f2-530e-4a50-b68f-563045268648 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'ANYRUN TI Get Intelligence'
Threat Intelligence IoC Lookup

Type: **investigate**  
Read only: **True**

Perform investigative actions by using the ANY.RUN Threat Intelligence Portal API method. This action requires <b>ANY.RUN TI License</b>. For more information about available parameters refer to official documentation (https://any.run/api-documentation/).

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Sha256** |  optional  | Sha256 (Size range: 2-256) | string |  `hash`  `sha256` 
**Sha1** |  optional  | Sha1 (Size range: 2-256) | string |  `hash`  `sha1` 
**MD5** |  optional  | MD5 (Size range: 2-256) | string |  `hash`  `md5` 
**ThreatName** |  optional  | Name of threat (Size range: 2-256) | string | 
**ThreatLevel** |  optional  | Threat level (Default: <empty>) | string | 
**TaskType** |  optional  | Task run type (Default: <empty>) | string | 
**SubmissionCountry** |  optional  | Submission country (Size range: 2-256) | string | 
**OS** |  optional  | Operation system (Default: <empty> - not used) | string | 
**OSSoftwareSet** |  optional  | Operation system software (Default: <empty> - not used) | string | 
**OSBitVersion** |  optional  | Operation system bitness (Default: <empty> - not used) | numeric | 
**RegistryKey** |  optional  | Registry key (Size range: 2-256) | string | 
**RegistryName** |  optional  | Registry name (Size range: 2-256) | string | 
**RegistryValue** |  optional  | Registry value (Size range: 2-256) | string | 
**ModuleImagePath** |  optional  | Module image path (Size range: 2-256) | string |  `file path` 
**RuleThreatLevel** |  optional  | Rule threat level (Default: <empty> - not used) | string | 
**RuleName** |  optional  | Rule name (Size range: 2-256) | string | 
**MITRE** |  optional  | MITRE (Size range: 2-256) | string | 
**ImagePath** |  optional  | Process image path (Size range: 2-256) | string |  `file path` 
**CommandLine** |  optional  | Command line (Size range: 2-256) | string |  `process name` 
**InjectedFlag** |  optional  | Injected flag (Default: <empty> - not used) | string | 
**DestinationIp** |  optional  | Destination ip (Size range: 2-256) | string |  `ip` 
**DestinationPort** |  optional  | Destination port (Default: <empty> - not used) (Size range: 1-65535) | numeric |  `port` 
**DestinationIPASN** |  optional  | Destination IPASN (Size range: 2-256) | string | 
**DestinationIPGeo** |  optional  | Destination IP Geo (Size range: 2-256) | string | 
**DomainName** |  optional  | Domain name (Size range: 2-256) | string |  `domain` 
**FileName** |  optional  | File name (Size range: 2-256) | string |  `file name` 
**SuricataClass** |  optional  | Suricata class (Default: <empty> - not used) | string | 
**SuricataMessage** |  optional  | Suricata message (Size range: 2-256) | string | 
**SuricataThreatLevel** |  optional  | Suricata threat level (Default: <empty> - not used) | string | 
**SuricataID** |  optional  | Suricata ID (Size range: 2-256) | string | 
**URL** |  optional  | URL (Size range: 2-256) | string |  `url` 
**HTTPRequestContentType** |  optional  | HTTP request content type (Size range: 2-256) | string | 
**HTTPResponseContentType** |  optional  | HTTP response content type (Size range: 2-256) | string | 
**HTTPRequestFileType** |  optional  | HTTP request file type (Size range: 2-256) | string | 
**HTTPResponseFileType** |  optional  | HTTP response file type (Size range: 2-256) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.sha256 | string |  `hash`  `sha256`  |  
action_result.parameter.sha1 | string |  `hash`  `sha1`  |  
action_result.parameter.md5 | string |  `hash`  `md5`  |  
action_result.parameter.threatname | string |  |  
action_result.parameter.threatlevel | string |  |  
action_result.parameter.tasktype | string |  |  
action_result.parameter.submissioncountry | string |  |  
action_result.parameter.os | string |  |  
action_result.parameter.ossoftwareset | string |  |  
action_result.parameter.osbitversion | numeric |  |  
action_result.parameter.registrykey | string |  |  
action_result.parameter.registryname | string |  |  
action_result.parameter.registryvalue | string |  |  
action_result.parameter.moduleimagepath | string |  `file path`  |  
action_result.parameter.rulethreatlevel | string |  |  
action_result.parameter.rulename | string |  |  
action_result.parameter.mitre | string |  |  
action_result.parameter.imagepath | string |  `file path`  |  
action_result.parameter.commandline | string |  |  
action_result.parameter.injectedflag | string |  |  
action_result.parameter.destinationip | string |  `ip`  |  
action_result.parameter.destinationport | numeric |  `port`  |  
action_result.parameter.destinationipasn | string |  |  
action_result.parameter.destinationipgeo | string |  |  
action_result.parameter.domainname | string |  `domain`  |  
action_result.parameter.filename | string |  `file name`  |  
action_result.parameter.suricataclass | string |  |  
action_result.parameter.suricatamessage | string |  |  
action_result.parameter.suricatathreatlevel | string |  |  
action_result.parameter.suricataid | string |  |  
action_result.parameter.url | string |  `url`  |  
action_result.parameter.httprequestcontenttype | string |  |  
action_result.parameter.httpresponsecontenttype | string |  |  
action_result.data.\*.summary.threatLevel | string |  |  
action_result.data.\*.summary.detectedType | string |  |  
action_result.data.\*.summary.lastSeen | string |  |  
action_result.summary.\*.Type | string |  |  
action_result.summary.\*.Count | numeric |  |  
action_result.summary.\*.str | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 