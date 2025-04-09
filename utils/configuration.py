# Copyright (c) 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re


class Configuration:
    """Analysis configuration class for specifying optional parameters
    for the sandbox, where new submission analysis will be performed.

    Learn more about available parameters in the ANY.RUN Sandbox API in:
    https://any.run/api-documentation/
    """

    # pylint: disable=line-too-long
    ATTRIBUTES_STR = [
        "env_os",
        "env_version",
        "env_type",
        "env_locale",
        "opt_network_geo",
        "opt_network_residential_proxy_geo",
        "opt_privacy_type",
        "obj_ext_cmd",
        "obj_ext_browser",
        "obj_ext_useragent",
        "obj_url",
    ]
    ATTRIBUTES_BOOL = [
        "opt_network_connect",
        "opt_network_fakenet",
        "opt_network_tor",
        "opt_network_mitm",
        "opt_network_residential_proxy",
        "opt_kernel_heavyevasion",
        "opt_automated_interactivity",
        "auto_confirm_uac",
        "run_as_root",
        "obj_ext_extension",
        "opt_privacy_hide_browser",
    ]
    ATTRIBUTES_INT = ["env_bitness", "opt_timeout"]

    FILE_SPECIFIC_ATTRIBUTES = ["obj_ext_startfolder"]
    LINK_SPECIFIC_ATTRIBUTES = ["obj_ext_elevateprompt"]

    @classmethod
    def _process_os(cls, param: dict) -> dict:
        """Process the os parameter"""
        # convert configuration id to env_os, env_version, env_bitness, env_type
        os = param.pop("os")
        convert_srt = r"(Linux|Windows)([\d\.]+)x(32|64)_(office|clean|complete)"
        env_os, env_version, env_bitness, env_type = (re.search(convert_srt, os)).groups()

        # update params
        new_params = {
            "env_os": env_os.lower(),
            "env_version": env_version,
            "env_bitness": env_bitness,
            "env_type": env_type,
        } | param

        # remove conflicting options
        if env_os == "Windows":
            new_params.pop("run_as_root", None)
        elif env_os == "Linux":
            new_params.pop("auto_confirm_uac", None)
            new_params.pop("obj_ext_elevateprompt", None)

        return new_params

    @classmethod
    def _validate_integer(cls, parameter: str, key: str, allow_zero: bool = False) -> tuple[str, str]:
        """
        Validate integer input

        :param action_result: ActionResult object
        :param parameter: Parameter value to validate
        :param key: Key for error message
        :param allow_zero: Allow zero value
        :return: Tuple of status and parameter value
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    raise ValueError(f"Please provide a valid integer value in the {key}")
                parameter = int(parameter)
            except:  # pylint: disable=bare-except
                raise ValueError(f"Please provide a valid integer value in the {key}")

            if parameter < 0:
                raise ValueError(f"Please provide a valid non-negative integer value in the {key}")
            if not allow_zero and parameter == 0:
                raise ValueError(f"Please provide a valid non-zero integer value in the {key}")

        return parameter

    @classmethod
    def from_dict(cls, attr_dict: dict):
        """Creates an object from its dictionary representation."""
        if not isinstance(attr_dict, dict):
            raise ValueError(f"Expecting dictionary, got: {type(attr_dict).__name__}")
        return cls(**attr_dict)

    @classmethod
    def get_config(cls, param: dict, is_file: bool = False) -> dict:
        """Get configuration from parameters"""
        params = cls._process_os(param)

        if is_file:
            attributes = cls.ATTRIBUTES_STR + cls.ATTRIBUTES_BOOL + cls.ATTRIBUTES_INT + cls.FILE_SPECIFIC_ATTRIBUTES
        else:
            attributes = cls.ATTRIBUTES_STR + cls.ATTRIBUTES_BOOL + cls.ATTRIBUTES_INT + cls.LINK_SPECIFIC_ATTRIBUTES

        data = {key: value for key, value in params.items() if key in attributes}
        for attr in cls.ATTRIBUTES_INT:
            if attr in data:
                data[attr] = cls._validate_integer(data[attr], attr)

        if "opt_timeout" not in data:
            data["opt_timeout"] = 10

        return data
