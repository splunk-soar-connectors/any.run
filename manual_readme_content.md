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
	- anyrun-sdk-1.8.4
```
