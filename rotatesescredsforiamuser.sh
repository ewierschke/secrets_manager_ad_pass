#/bin/bash
# This script attempts to create a new access key for use with SES in postfix

username=<username>
adminmailtoaddress=<adminemail>

log()
{
  echo \[$(date +%d%m%Y-%H:%M:%S)\] "$1"
  echo \[$(date +%d%m%Y-%H:%M:%S)\] "$1" >> /var/log/rotatesescredsforiamuser.log
}

log "Begin execution of ses rotate script on ${HOSTNAME}"

yum -y install epel-release
yum-config-manager --enable epel
if ! yum list installed jq mutt postfix ; then
  yum -y install jq mutt postfix wget
fi

#create python to create smtp password from access key secret
log "Create python script"
(
  printf "#!/usr/bin/env python3\n"
  printf "# ref - https://docs.aws.amazon.com/ses/latest/DeveloperGuide/smtp-credentials.html\n"
  printf "\n"
  printf "import hmac\n"
  printf "import hashlib\n"
  printf "import base64\n"
  printf "import argparse\n"
  printf "\n"
  printf "# Values that are required to calculate the signature. These values should\n"
  printf "# never change.\n"
  printf "DATE = \"11111111\"\n"
  printf "SERVICE = \"ses\"\n"
  printf "MESSAGE = \"SendRawEmail\"\n"
  printf "TERMINAL = \"aws4_request\"\n"
  printf "VERSION = 0x04\n"
  printf "\n"
  printf "def sign(key, msg):\n"
  printf "    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()\n"
  printf "\n"
  printf "def calculateKey(secretAccessKey, region):\n"
  printf "    signature = sign((\"AWS4\" + secretAccessKey).encode('utf-8'), DATE)\n"
  printf "    signature = sign(signature, region)\n"
  printf "    signature = sign(signature, SERVICE)\n"
  printf "    signature = sign(signature, TERMINAL)\n"
  printf "    signature = sign(signature, MESSAGE)\n"
  printf "    signatureAndVersion = bytes([VERSION]) + signature\n"
  printf "    smtpPassword = base64.b64encode(signatureAndVersion)\n"
  printf "    print(smtpPassword.decode('utf-8'))\n"
  printf "\n"
  printf "def main():\n"
  printf "    parser = argparse.ArgumentParser(description='Convert a Secret Access Key for an IAM user to an SMTP password.')\n"
  printf "    parser.add_argument('--secret',\n"
  printf "            help='The Secret Access Key that you want to convert.',\n"
  printf "            required=True,\n"
  printf "            action=\"store\")\n"
  printf "    parser.add_argument('--region',\n"
  printf "            help='The name of the AWS Region that the SMTP password will be used in.',\n"
  printf "            required=True,\n"
  printf "            choices=['us-east-1','us-west-2','eu-west-1'],\n"
  printf "            action=\"store\")\n"
  printf "    args = parser.parse_args() \n"
  printf "\n"
  printf "    calculateKey(args.secret,args.region)\n"
  printf "\n"
  printf "main()\n"
) > /usr/local/bin/key2smtppass.py

#create sasl_passwd_template
log "Create sasl_passwd_template"
(
  printf "# SES us-east-1\n"
  printf "[email-smtp.us-east-1.amazonaws.com]:25 __AKID__:__SMTPPASSWORD__\n"
  printf "[email-smtp.us-east-1.amazonaws.com]:587 __AKID__:__SMTPPASSWORD__\n"
  printf "\n"
  printf "# SES us-west-2\n"
  printf "[email-smtp.us-west-2.amazonaws.com]:25 __AKID__:__SMTPPASSWORD__\n"
  printf "[email-smtp.us-west-2.amazonaws.com]:587 __AKID__:__SMTPPASSWORD__\n"
  printf "\n"
) > /usr/local/bin/sasl_passwd_template

#create .muttsesrotaterc
log "Create mutt config"
echo 'set realname="SES Rotate"' >> /root/.muttsesrotaterc
mailfromdomain=$(cat /usr/local/bin/mailfromdomain)
echo 'set from="sesrotate@'$mailfromdomain'"' >> /root/.muttsesrotaterc
echo 'set use_from = yes' >> /root/.muttsesrotaterc
echo 'set edit_headers = yes' >> /root/.muttsesrotaterc
echo 'set use_envelope_from = yes' >> /root/.muttsesrotaterc

#create sescredrotatedemail
log "Create admin email template"
echo '<html><head></head><body>IAM access keys used for SES sending have been successfully rotated: <br><br>IAM Username: __IAMUSERNAME__, EC2 Instance ID: __EC2ID__, <br><br><br></body></html>' > /usr/local/bin/sescredrotatedemail.html

log "Get current access keys"
inactivestatus=Inactive
currentkeys=$(aws iam list-access-keys --user-name $username)
#check key count
keycount=$(jq -r '.AccessKeyMetadata | length' <<< $currentkeys)
#if 2 keys exist for user, delete inactive or oldest key
log "${username} currently has ${keycount} access keys"
if [ $keycount == 2 ]
then
  #find and delete inactive key
  for (( c=0; c<$keycount; c++ ))
  do 
    thiskey=$(jq -r .AccessKeyMetadata[$c] <<< $currentkeys)
    thiskeystatus=$(jq -r .AccessKeyMetadata[$c].Status <<< $currentkeys)
    if [ $thiskeystatus == $inactivestatus ]
    then
      log "One key is inactive, deleting inactive key..."
      #delete inactive key
      thiskeyid=$(jq -r .AccessKeyId <<< $thiskey)
      aws iam delete-access-key --user-name $username --access-key-id $thiskeyid
    fi
  done
  currentkeys=$(aws iam list-access-keys --user-name $username)
  keycount=$(jq -r '.AccessKeyMetadata | length' <<< $currentkeys)
  if [ $keycount == 2 ]
  #since previous check didn't reduce keycount to 1, both keys are set to active
  then
    log "No inactive keys, deleting older key..."
    #compare dates of keys, delete older(smaller date) key
    key0date=$(jq -r .AccessKeyMetadata[0].CreateDate <<< $currentkeys)
    key1date=$(jq -r .AccessKeyMetadata[1].CreateDate <<< $currentkeys)
    key0dateseconds=$(date -d $key0date +"%s")
    key1dateseconds=$(date -d $key1date +"%s")
    if [ $key0dateseconds -lt $key1dateseconds ]
    then
      log "key0 is older than key1, deleting key0..."
      key0id=$(jq -r .AccessKeyMetadata[0].AccessKeyId <<< $currentkeys)
      aws iam delete-access-key --user-name $username --access-key-id $key0id
    else 
      log "key1 is older than key0, deleting key1..."
      key1id=$(jq -r .AccessKeyMetadata[1].AccessKeyId <<< $currentkeys)
      aws iam delete-access-key --user-name $username --access-key-id $key1id
    fi
  fi
fi
#check key count again just for verification
currentkeys=$(aws iam list-access-keys --user-name $username)
keycount=$(jq -r '.AccessKeyMetadata | length' <<< $currentkeys)
#creat new key, new sasl_passwd contents, send test email, and set old key to inactive
if [ $keycount -lt 2 ]
then 
  log "Less than 2 access keys, creating new key..."
  existingkey=$(aws iam list-access-keys --user-name $username)
  existingkeyid=$(jq -r .AccessKeyMetadata[0].AccessKeyId <<< $existingkey)
  #create new key and secret
  newkey=$(aws iam create-access-key --user-name $username)
  newkeyid=$(jq -r .AccessKey.AccessKeyId <<< $newkey)
  newkeysecret=$(jq -r .AccessKey.SecretAccessKey <<< $newkey)
  #create smtp password from secret
  log "Converting secret to smtp_password..."
  SMTP_PASSWORD=$(python3 /usr/local/bin/key2smtppass.py --secret $newkeysecret --region us-east-1)
  #copy sasl_passwd template and adjust contents
  log "Copy sasl_passwd_template..."
  cp -rf /usr/local/bin/sasl_passwd_template /etc/postfix/sasl_passwd
  log "Adjust new sasl_passwd..."
  /usr/bin/sed -i \
    -e "s|__AKID__|$newkeyid|" \
    -e "s|__SMTPPASSWORD__|$SMTP_PASSWORD|" \
  /etc/postfix/sasl_passwd
  now=$(date -d "today" +"%Y.%m.%d %H:%M:%S")
  nowcomment="# ${now}"
  echo $nowcomment >> /etc/postfix/sasl_passwd
  #use new creds
  log "Use new sasl_passwd"
  /sbin/postmap /etc/postfix/sasl_passwd
  #add instance id and ses iam username to email
  log "Get ec2 instance id..."
  ec2id="`wget -q -O - http://169.254.169.254/latest/meta-data/instance-id || die \"wget instance-id has failed: $?\"`"
  log "Adjust email template..."
  /usr/bin/sed -i \
    -e "s|__IAMUSERNAME__|$username|" \
    -e "s|__EC2ID__|$ec2id|" \
  /usr/local/bin/sescredrotatedemail.html
  #send test email to admin
  log "Send admin email using new creds..."
  mutt -F /root/.muttsesrotaterc -e 'set content_type=text/html' -s "SES Credential Rotated" $adminmailtoaddress < /usr/local/bin/sescredrotatedemail.html
  if [[ $? -eq 0 ]]
  then 
    log "Make old access key inactive..."
    aws iam update-access-key --user-name $username --access-key-id $existingkeyid --status $inactivestatus
  fi
  log "Created new key..."
fi 
log "Done..."