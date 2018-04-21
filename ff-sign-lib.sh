#!/bin/bash

declare -A ff_lib=()

ff_get_curtime(){
  # avoid spawning a process if we have a capable bash
  if [ ${BASH_VERSINFO[0]} -ge 4 ] && [ ${BASH_VERSINFO[1]} -ge 2 ]; then
    printf '%(%Y-%m-%d %H:%M:%S)T\n' -1
  else
    "${ff_lib['date']}" +"%Y-%m-%d %H:%M:%S"
  fi
}

ff_log(){
  local msg=$1
  local curtime=$(ff_get_curtime)
  echo "$curtime $msg"
}

ff_check_required_binaries(){

  ff_log "Checking required binaries..."

  local retcode=0

  ff_lib['curl']=$(command -v curl)
  ff_lib['date']=$(command -v date)
  ff_lib['awk']=$(command -v awk)
  ff_lib['zip']=$(command -v zip)
  ff_lib['jq']=$(command -v jq)
  ff_lib['openssl']=$(command -v openssl)

  ( [ "${ff_lib['curl']}" != "" ] && \
    [ "${ff_lib['date']}" != "" ] && \
    [ "${ff_lib['awk']}" != "" ] && \
    [ "${ff_lib['openssl']}" != "" ] && \
    [ "${ff_lib['jq']}" != "" ] && \
    [ "${ff_lib['zip']}" != "" ] ) || \
  { ff_log "Cannot find needed binaries, make sure you have curl, awk, zip, openssl and jq in your PATH" && return 1; }
}

ff_get_credentials(){

  ff_log "Getting API credentials..."

  local ff_userdef_cred_function=ff_get_userdef_credentials

  if ! declare -F $ff_userdef_cred_function >/dev/null; then
    ff_log "Function '$ff_userdef_cred_function()' does not exist, you must define it and make sure it sets variables 'ff_lib[jwt_issuer]', 'ff_lib[jwt_secret]'"
    return 1
  fi

  $ff_userdef_cred_function   # user MUST implement this

  ( [ "${ff_lib['jwt_issuer']}" != "" ] && \
    [ "${ff_lib['jwt_secret']}" != "" ] ) || \

    { ff_log "Cannot get hubic credentials; make sure '$ff_userdef_cred_function()' sets variables 'ff_lib[jwt_issuer]', 'ff_lib[jwt_secret]'" && return 1; }
}

ff_api_init(){

  ff_lib['api_initialized']="0"
  ff_log "API initialization starting..."

  ff_check_required_binaries || return 1
  ff_get_credentials || return 1

  ff_lib['addon_dir']=$1

  if [ "${ff_lib['addon_dir']}" = "" ]; then
    ff_log "Addon dir not given, returning"
    return 1
  fi

  if [ ! -d "${ff_lib['addon_dir']}" ]; then
    ff_log "Addon dir ${ff_lib['addon_dir']} not found, returning"
    return 1
  fi

  local manifest="${ff_lib['addon_dir']}/manifest.json"

  if [ ! -f "$manifest" ]; then
    ff_log "Manifest not found in ${ff_lib['addon_dir']}, returning"
    return 1
  fi

  # extract addon ID and version
  ff_lib['addon_id']=$(${ff_lib['jq']} -r '.applications.gecko.id' < "$manifest")
  if [ "${ff_lib['addon_id']}" = "" ]; then
    ff_log "Cannot find addon ID in $manifest, terminating"
    return 1
  fi

  ff_lib['current_addon_version']=$(${ff_lib['jq']} -r '.version' < "$manifest")

  if [ "${ff_lib['current_addon_version']}" = "" ]; then
    ff_log "Cannot find addon version in $manifest, terminating"
    return 1
  fi

  ff_log "API initialization completed"

  ff_lib['api_initialized']="1"

}

ff_do_jwt(){

  ff_check_api_initialized || return 1

  local jti_nonce="${RANDOM}.$(TZ=UTC date +%s%N)"

  local start_t=$(TZ=UTC date +%s)
  local end_t=$(( start_t + 60 ))

  local jwt_header_json='{ "alg": "HS256", "typ": "JWT" }' #, "kid": "0001"}'
  local jwt_payload_json='{ "iss": "'"${ff_lib['jwt_issuer']}"'", "jti": "'"${jti_nonce}"'", "iat": '"${start_t}"', "exp": '"${end_t}"' }'
  local jwt_hp_base64=$(printf '%s' "${jwt_header_json}" | ${ff_lib['openssl']} base64 -A).$(printf '%s' "${jwt_payload_json}" | ${ff_lib['openssl']} base64 -A)
  local signature=$(printf '%s' "${jwt_hp_base64}" | ${ff_lib['openssl']} dgst -binary -sha256 -hmac "${ff_lib['jwt_secret']}" | ${ff_lib['openssl']} base64 -A)
  echo "${jwt_hp_base64}.${signature}"
}

ff_check_api_initialized(){
  if [ "${ff_lib['api_initialized']}" != "1" ] || [ "${ff_lib['jwt_issuer']}" = "" ] || [ "${ff_lib['jwt_secret']}" = "" ]; then
    ff_log "API not initialized, call ff_api_init first"
    return 1
  fi
}

ff_do_curl(){

  local result

  result=$(
    ${ff_lib['curl']} -H "Expect:" -s -D- "$@" 
  )

  ff_lib['last_http_headers']=$(${ff_lib['awk']} '/^\r$/{ exit }1' <<< "$result")
  ff_lib['last_http_body']=$(${ff_lib['awk']} 'ok; /^\r$/ { ok = 1 }' <<< "$result")
  ff_lib['last_http_code']=$(${ff_lib['awk']} '/^HTTP/ { print $2; exit }' <<< "$result")

}

ff_parse_args(){

  ff_lib['new_addon_version']=
  ff_lib['xpi_file']=
  ff_lib['zip_file']=
  ff_lib['result_json']=
  ff_lib['addon_download_url']=
  ff_lib['addon_listed']=

  while [ $# -gt 0 ]; do

    case $1 in
      -v|--version)
        ff_lib['new_addon_version']=$2
        shift 2
        ;;
      -x|--xpi-file)
        ff_lib['xpi_file']=$2
        shift 2
        ;;
      -z|--zip-file)
        ff_lib['zip_file']=$2
        shift 2
        ;;
      -j|--json)
        ff_lib['result_json']=$2
        shift 2
        ;;
      -u|--xpi-url)
        ff_lib['addon_download_url']=$2
        shift 2
        ;;
      -l|--listed)
        ff_lib['addon_listed']=$2
        shift 2
        ;;
 
      *)
        ff_log "Unknown option/arg: '$1', skipping..."
        shift
        ;;
    esac

  done

  if [[ ! "${ff_lib['addon_listed']}" =~ ^1$ ]]; then
    ff_lib['addon_listed']="unlisted"
  else
    ff_lib['addon_listed']="listed"
  fi
}

ff_upload_addon(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  ff_create_zip "$@" || return 1

  local jwt_token=$(ff_do_jwt)
  ff_do_curl -g -XPUT "https://addons.mozilla.org/api/v3/addons/${ff_lib['addon_id']}/versions/${ff_lib['new_addon_version']}/" -H "Authorization: JWT ${jwt_token}" --form "upload=@${ff_lib['zip_file']}" --form "channel=${ff_lib['addon_listed']}"

  rm -rf "${ff_lib['zip_file']}"

  ff_log "Upload HTTP code: ${ff_lib['last_http_code']}"

  if [ "${ff_lib['last_http_code']}" != "201" ] && [ "${ff_lib['last_http_code']}" != "202" ]; then
    return 1
  else
    return 0
  fi

}

ff_create_zip(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "${ff_lib['new_addon_version']}" = "" ]; then    
    ff_log "New addon version not specified, terminating"
    return 1
  fi

  local manifest="${ff_lib['addon_dir']}/manifest.json"

  if [ "${ff_lib['zip_file']}" = "" ]; then
    ff_lib['zip_file']=/tmp/${ff_lib['addon_id']}-${ff_lib['new_addon_version']}.zip
  fi

  local addon_temp_dir=/tmp/${ff_lib['addon_id']}-${ff_lib['new_addon_version']}

  rm -rf "${ff_lib['zip_file']}" "$addon_temp_dir"

  cp -a "${ff_lib['addon_dir']}" "$addon_temp_dir"
  
  local temp_manifest=$addon_temp_dir/manifest.json
  local new_manifest=$(${ff_lib['jq']} --arg new_version "${ff_lib['new_addon_version']}" '.version = $new_version' < "$temp_manifest")
  echo "$new_manifest" > "$temp_manifest"

  ( cd "$addon_temp_dir" && ${ff_lib['zip']} -q -r -FS "${ff_lib['zip_file']}" .)

  local result=$?

  rm -rf "$addon_temp_dir"

  if [ $result -ne 0 ]; then
    ff_log "Error creating zip file ${ff_lib['zip_file']}, terminating"
    return 1
  fi

}

ff_wait_validation(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "${ff_lib['result_json']}" = "" ]; then
    ff_log "No JSON passed for validation, terminating"
    return 1
  fi
  
  local new_addon_version=$(${ff_lib['jq']} -r '.version' <<< "${ff_lib['result_json']}")

  if [ "$new_addon_version" = "" ]; then
    ff_log "Cannot find addon version in the JSON, terminating"
    return 1
  fi

  ff_log "Waiting for validation of addon ${ff_lib['addon_id']}, version $new_addon_version"

  local automated_signing=$(${ff_lib['jq']} -r '.automated_signing' <<< "${ff_lib['result_json']}")

  while true; do

    local processed=$(${ff_lib['jq']} -r '.processed' <<< "${ff_lib['result_json']}")
    local valid=$(${ff_lib['jq']} -r '.valid' <<< "${ff_lib['result_json']}")
    local validation_results=$(${ff_lib['jq']} '.validation_results' <<< "${ff_lib['result_json']}")
    local reviewed=$(${ff_lib['jq']} -r '.reviewed' <<< "${ff_lib['result_json']}")
    local passed_review=$(${ff_lib['jq']} -r '.passed_review' <<< "${ff_lib['result_json']}")
    local success=$(${ff_lib['jq']} -r '.validation_results.success' <<< "${ff_lib['result_json']}")
    local errors=$(${ff_lib['jq']} -r '.validation_results.errors' <<< "${ff_lib['result_json']}")
    local warnings=$(${ff_lib['jq']} -r '.validation_results.warnings' <<< "${ff_lib['result_json']}")
    local download_url=$(${ff_lib['jq']} -r '.files[0].download_url' <<< "${ff_lib['result_json']}")

    ff_log "Processed: $processed, valid: $valid, reviewed: $reviewed, passed_review: $passed_review"

    if [ "$processed" = "true" ]; then
      if [ "$valid" = "false" ]; then
        ff_log "Validation failed, results: $validation_results"
        return 1
      else
        if [ "$automated_signing" != "true" ]; then
          ff_log "Addon validated, no automated signing, returning"
          return 0
        fi

        if [ "$reviewed" = "true" ]; then
          if [ "$passed_review" = "false" ]; then
            ff_log "Review failed, returning"
            return 1
          else
            ff_log "Validated and reviewed, success: $success, errors: $errors, warnings: $warnings"

            # all good, checking for download URL

            if [ "$download_url" != "null" ]; then
              ff_log "Signing completed, download URL is $download_url"
              ff_lib['addon_download_url']=$download_url
              return
            else
              ff_log "Download URL not yet available..."
            fi
          fi    
        fi
      fi
    fi

    sleep 3
    local jwt_token=$(ff_do_jwt)
    ff_do_curl -g -XGET "https://addons.mozilla.org/api/v3/addons/${ff_lib['addon_id']}/versions/${new_addon_version}/" -H "Authorization: JWT ${jwt_token}"
    ff_log "Status after retrying is ${ff_lib['last_http_code']}"
    ff_lib['result_json']=${ff_lib['last_http_body']}
  done

}

ff_download_xpi_file(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "${ff_lib['new_addon_version']}" = "" ]; then
    ff_log "Must specify version to download"
    return 1
  fi

  if [ "${ff_lib['xpi_file']}" = "" ]; then
    ff_lib['xpi_file']=/tmp/${ff_lib['addon_id']}-${ff_lib['new_addon_version']}.xpi
  fi

  if [ "${ff_lib['addon_download_url']}" = "" ]; then
    ff_log "Must specify URL to download the XPI file"
    return 1
  fi

  local jwt_token=$(ff_do_jwt)

  ff_do_curl -o "${ff_lib['xpi_file']}" -g "${ff_lib['addon_download_url']}" -H "Authorization: JWT ${jwt_token}"

  ff_log "Downloaded file saved at ${ff_lib['xpi_file']}"

}

ff_accept_new_version(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "${ff_lib['new_addon_version']}" = "" ]; then    
    ff_log "New addon version not specified, terminating"
    return 1
  fi

  local manifest="${ff_lib['addon_dir']}/manifest.json"

  if [ ! -f "$manifest" ]; then
    ff_log "Manifest not found at $manifest, terminating"
    return 1
  fi

  local new_manifest=$(${ff_lib['jq']} --arg new_version "${ff_lib['new_addon_version']}" '.version = $new_version' < "$manifest")
  echo "$new_manifest" > "$manifest"

  ff_log "Version ${ff_lib['new_addon_version']} written to manifest"
}
