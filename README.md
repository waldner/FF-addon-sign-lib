# FF-addon-sign-lib

Small shell helper to build and upload Firefox (Web)extensions

## Dependencies

The only dependencies needed are [bash](https://www.gnu.org/software/bash/), [curl](https://curl.haxx.se/) and [perl](https://www.perl.org/), zip, [jq](https://stedolan.github.io/jq/), [openssl](https://www.openssl.org/), base64.

## Installation

No special installation needed. Just put **`ff-sign-lib.sh`** wherever you want. You have to know the location because you'll have to source it in your script.

## Getting started

- You should already have a directory containing your addon in source (ie, unpacked) form, with a manifest and all needed files. See [the official documentation](https://developer.mozilla.org/en-US/Add-ons/WebExtensions) for more information.

- Find out your Mozilla API credentials. You can find them by logging in to Mozilla, then going to your profile amd than "tools" -> "Manage API keys". You need the **JWT issuer** and **JWT secret** values.

- Implement a function called `ff_get_userdef_credentials` that sets some environment variables with suitable values (`ff_lib['jwt_issuer']` and `ff_lib['jwt_secret']` from the previous step).

- Source `ff-sign-lib.sh` in your script

- Call `ff_api_init` passing the location of your addon as argument, and check that it returns without errors.

- At this point, you can perform API operations by invoking functions like `ff_upload_file`, `ff_wait_validation` and others. See below for more.

- The whole process does not modify any file in your original source directory, so if you want to modify the manifest.json to include the new addon version, call `ff_accept_new_version` to do it.

## Internals

After each API function invocation, the three variables `ff_lib['last_http_headers']`, `ff_lib['last_http_body']` and `ff_lib['last_http_code']` contain what their name says, so they can be inspected in your code for extra control.

Each file API operation ends up invoking `ff_do_curl` internally, after setting the appropriate global variables (via `ff_parse_args`).

## Sample code


```
#!/bin/bash

ff_get_userdef_credentials(){
  ff_lib['jwt_issuer']='yyyy:yyyyyyyy:yyy'
  ff_lib['jwt_secret']='xxxxxxxxxxxxxxxxxxxxxxx'
}

. ff-sign-lib.sh

addon_dir=/path/to/addon

# this sets $ff_addon_id and $ff_current_addon_version
ff_api_init "$addon_dir" || { echo "Error initializing API, terminating" >&2 && exit 1; }

echo "Current addon version for $ff_addon_id is $ff_current_addon_version"

new_version=10.1

# or:
# printf 'Enter new addon version: '; read new_version
# or read it from command line, or whatever

ff_upload_addon -v "$new_version" || { echo "Error uploading addon, terminating" >&2 && exit 1; }

result_json=${ff_lib['last_http_body']}

# this sets ff_lib['addown_download_url'] if successful
ff_wait_validation -j "$result_json" || { echo "Error during validation/review, terminating" >&2 && exit 1; }

ff_download_xpi_file -u "${ff_lib['addon_download_url']}" -v "$new_version"

# write new version to manifest
ff_accept_new_version -v "$new_version"

echo "Signing done"

```

