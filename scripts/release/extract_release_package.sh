#!/bin/bash
set -e     # every single step failure causes script to stop immediatelly

extract_location="${HOME}/openness_release_packages"
package_name='openness_release_package.tgz'

echo -en "\nEnter location to extract packages [ ${extract_location} ]: "
read user_location

[[ "$user_location" ]] && extract_location="$user_location"

if ! [[ -f "$package_name" ]]; then
  echo "ERROR: OpenNESS release package not found. File missing in current folder: $package_name"
  exit 1
fi

if [[ -d "$extract_location" ]]; then
  echo "ERROR: Folder already exists"
  exit 1
fi

echo "Extracting package..."
mkdir -p "$extract_location"
tar xfz "$package_name" -C "$extract_location"
echo "...done"

echo "Copying offline content to user home folder"
[[ -d ${HOME}/go ]] || mkdir ${HOME}/go
tar xf $extract_location/common/cached-modules.tgz -C ${HOME}/go/
echo "...done"
echo -e "\n SUCCESS !\nAll packages extracted successfully to: $extract_location\n"
