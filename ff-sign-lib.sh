#!/bin/bash

ff_get_curtime(){
  # avoid spawning a process if we have a capable bash
  if [ ${BASH_VERSINFO[0]} -ge 4 ] && [ ${BASH_VERSINFO[1]} -ge 2 ]; then
    printf '%(%Y-%m-%d %H:%M:%S)T\n' -1
  else
    $perl -MTime::localtime -e '$tm = localtime; printf("%04d-%02d-%02d %02d:%02d:%02d\n", $tm->year+1900, ($tm->mon)+1, $tm->mday, $tm->hour, $tm->min, $tm->sec);'
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

  curl=$(command -v curl)
  perl=$(command -v perl)
  zip=$(command -v zip)
  jq=$(command -v jq)
  openssl=$(command -v openssl)

  ( [ "$curl" != "" ] && \
    [ "$perl" != "" ] && \
    [ "$openssl" != "" ] && \
    [ "$jq" != "" ] && \
    [ "$zip" != "" ] ) || \
  { ff_log "Cannot find needed binaries, make sure you have curl, perl and zip in your PATH" && return 1; }
}

ff_get_credentials(){

  ff_log "Getting API credentials..."

  local ff_userdef_cred_function=ff_get_userdef_credentials

  if ! declare -F $ff_userdef_cred_function >/dev/null; then
    ff_log "Function '$ff_userdef_cred_function()' does not exist, you must define it and make sure it sets variables 'ff_jwt_issuer', 'ff_jwt_secret'"
    return 1
  fi

  $ff_userdef_cred_function   # user MUST implement this

  ( [ "$ff_jwt_issuer" != "" ] && \
    [ "$ff_jwt_secret" != "" ] ) || \

    { ff_log "Cannot get hubic credentials; make sure '$ff_userdef_cred_function()' sets variables 'ff_jwt_issuer', 'ff_jwt_secret'" && return 1; }
}

ff_api_init(){

  ff_api_initialized="0"
  ff_log "API initialization starting..."

  ff_check_required_binaries || return 1
  ff_get_credentials || return 1

  ff_addon_dir=$1

  if [ "$ff_addon_dir" = "" ]; then
    ff_log "Addon dir not given, returning"
    return 1
  fi

  if [ ! -d "$ff_addon_dir" ]; then
    ff_log "Addon dir $ff_addon_dir not found, returning"
    return 1
  fi

  local manifest="$ff_addon_dir/manifest.json"

  if [ ! -f "$manifest" ]; then
    ff_log "Manifest not found in $ff_addon_dir, returning"
    return 1
  fi

  # extract addon ID and version
  ff_addon_id=$(jq -r '.applications.gecko.id' < "$manifest")
  if [ "$ff_addon_id" = "" ]; then
    ff_log "Cannot find addon ID in $manifest, terminating"
    return 1
  fi

  ff_current_addon_version=$(jq -r '.version' < "$manifest")

  if [ "$ff_current_addon_version" = "" ]; then
    ff_log "Cannot find addon version in $manifest, terminating"
    return 1
  fi

  ff_log "API initialization completed"

  ff_api_initialized="1"

}

ff_do_jwt(){

  ff_check_api_initialized || return 1

  local jti_nonce="${RANDOM}.$(TZ=UTC date +%s%N)"

  local start_t=$(TZ=UTC date +%s)
  local end_t=$(( start_t + 60 ))

  local jwt_header_json='{ "alg": "HS256", "typ": "JWT" }' #, "kid": "0001"}'
  local jwt_payload_json='{ "iss": "'"${ff_jwt_issuer}"'", "jti": "'"${jti_nonce}"'", "iat": '"${start_t}"', "exp": '"${end_t}"' }'
  local jwt_hp_base64=$(printf '%s' "${jwt_header_json}" | $openssl base64 -w0).$(printf '%s' "${jwt_payload_json}" | $openssl base64 -w0)
  local signature=$(printf '%s' "${jwt_hp_base64}" | $openssl dgst -binary -sha256 -hmac "${ff_jwt_secret}" | $openssl base64 -w0)
  echo "${jwt_hp_base64}.${signature}"
}

ff_check_api_initialized(){
  if [ "$ff_api_initialized" != "1" ] || [ "$ff_jwt_issuer" = "" ] || [ "$ff_jwt_secret" = "" ]; then
    ff_log "API not initialized, call ff_api_init first"
    return 1
  fi
}

ff_do_curl(){

  local result

  result=$(
    $curl -H "Expect:" -s -D- "$@" 
  )

  ff_last_http_headers=$($perl -pe 'exit if /^\r$/;' <<< "$result")
  ff_last_http_body=$($perl -ne 'print if $ok; $ok = 1 if /^\r$/;' <<< "$result")
  ff_last_http_code=$($perl -ne 'if ($_ =~ /^HTTP/) { print ((split())[1]); exit };' <<< "$result")

}

ff_parse_args(){

  ff_new_addon_version=
  ff_xpi_file=
  ff_zip_file=
  ff_result_json=
  ff_addon_download_url=

  while [ $# -gt 0 ]; do

    case $1 in
      -v|--version)
        ff_new_addon_version=$2
        shift 2
        ;;
      -x|--xpi-file)
        ff_xpi_file=$2
        shift 2
        ;;
      -z|--zip-file)
        ff_zip_file=$2
        shift 2
        ;;
      -j|--json)
        ff_result_json=$2
        shift 2
        ;;
      -u|--xpi-url)
        ff_addon_download_url=$2
        shift 2
        ;;
      *)
        ff_log "Unknown option/arg: '$1', skipping..."
        shift
        ;;
    esac

  done

}

ff_upload_addon(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "$ff_new_addon_version" = "" ]; then    
    ff_log "New addon version not specified, terminating"
    return 1
  fi

  local manifest="$ff_addon_dir/manifest.json"

  if [ "$ff_zip_file" = "" ]; then
    ff_zip_file=/tmp/${ff_addon_id}-${ff_new_addon_version}.zip
  fi

  local addon_temp_dir=/tmp/${ff_addon_id}-${ff_new_addon_version}

  rm -rf "$ff_zip_file" "$addon_temp_dir"

  cp -a "$ff_addon_dir" "$addon_temp_dir"
  
  local temp_manifest=$addon_temp_dir/manifest.json
  local new_manifest=$($jq --arg new_version "$ff_new_addon_version" '.version = $new_version' < "$temp_manifest")
  echo "$new_manifest" > "$temp_manifest"

  ( cd "$addon_temp_dir" && $zip -q -r -FS "$ff_zip_file" .)

  if [ $? -ne 0 ]; then
    ff_log "Error creating zip file $ff_zip_file, terminating"
    return 1
  fi

  local jwt_token=$(ff_do_jwt)
  ff_do_curl -g -XPUT "https://addons.mozilla.org/api/v3/addons/${ff_addon_id}/versions/${ff_new_addon_version}/" -H "Authorization: JWT ${jwt_token}" --form "upload=@${ff_zip_file}"

  rm -rf "$addon_temp_dir" "$ff_zip_file"

  ff_log "Upload HTTP code: $ff_last_http_code"

  if [ "$ff_last_http_code" != "201" ] && [ "$ff_last_http_code" != "202" ]; then
    return 1
  else
    return 0
  fi

}

ff_wait_validation(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "$ff_result_json" = "" ]; then
    ff_log "No JSON passed for validation, terminating"
    return 1
  fi
  
  local new_addon_version=$($jq -r '.version' <<< "$ff_result_json")

  if [ "$new_addon_version" = "" ]; then
    ff_log "Cannot find addon version in the JSON, terminating"
    return 1
  fi

  ff_log "Waiting for validation of addon $ff_addon_id, version $new_addon_version"

  local automated_signing=$($jq -r '.automated_signing' <<< "$ff_result_json")

  while true; do

    local processed=$($jq -r '.processed' <<< "$ff_result_json")
    local valid=$($jq -r '.valid' <<< "$ff_result_json")
    local validation_results=$($jq '.validation_results' <<< "$ff_result_json")
    local reviewed=$($jq -r '.reviewed' <<< "$ff_result_json")
    local passed_review=$($jq -r '.passed_review' <<< "$ff_result_json")
    local success=$($jq -r '.validation_results.success' <<< "$ff_result_json")
    local errors=$($jq -r '.validation_results.errors' <<< "$ff_result_json")
    local warnings=$($jq -r '.validation_results.warnings' <<< "$ff_result_json")
    local download_url=$($jq -r '.files[0].download_url' <<< "$ff_result_json")

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
              ff_addon_download_url=$download_url
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
    ff_do_curl -g -XGET "https://addons.mozilla.org/api/v3/addons/${ff_addon_id}/versions/${new_addon_version}/" -H "Authorization: JWT ${jwt_token}"
    ff_log "Status after retrying is $ff_last_http_code"
    ff_result_json=$ff_last_http_body
  done

}

ff_download_xpi_file(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "$ff_new_addon_version" = "" ]; then
    ff_log "Must specify version to download"
    return 1
  fi

  if [ "$ff_xpi_file" = "" ]; then
    ff_xpi_file=/tmp/${ff_addon_id}-${ff_new_addon_version}.xpi
  fi

  if [ "$ff_addon_download_url" = "" ]; then
    ff_log "Must specify URL to download the XPI file"
    return 1
  fi

  local jwt_token=$(ff_do_jwt)

  set -x

  ff_do_curl -o "${ff_xpi_file}" -g "$ff_addon_download_url" -H "Authorization: JWT ${jwt_token}"

  set +x

  ff_log "Downloaded file saved at $ff_xpi_file"

}

ff_accept_new_version(){

  ff_check_api_initialized || return 1

  ff_parse_args "$@"

  if [ "$ff_new_addon_version" = "" ]; then    
    ff_log "New addon version not specified, terminating"
    return 1
  fi

  local manifest="$ff_addon_dir/manifest.json"

  if [ ! -f "$manifest" ]; then
    ff_log "Manifest not found at $manifest, terminating"
    return 1
  fi

  local new_manifest=$($jq --arg new_version "$ff_new_addon_version" '.version = $new_version' < "$manifest")
  echo "$new_manifest" > "$manifest"

  ff_log "Version $ff_new_addon_version written to manifest"
}
