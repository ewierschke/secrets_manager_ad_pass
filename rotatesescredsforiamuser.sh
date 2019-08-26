#/bin/bash
# This script attempts to create a new access key for use with SES in postfix
__SCRIPTNAME="rotatesescredsforiamuser.sh"

log()
{
  echo \[$(date +%d%m%Y-%H:%M:%S)\] "$1"
  echo \[$(date +%d%m%Y-%H:%M:%S)\] "$1" >> /var/log/rotatesescredsforiamuser.log
}  # ----------  end of function log  ----------

die()
{
    [ -n "$1" ] && log "$1"
    log "${__SCRIPTNAME} failed"'!'
    exit 1
}  # ----------  end of function die  ----------

usage()
{
    cat << EOT
  Usage:  ${__SCRIPTNAME} [options]
  Note:
  Script to create new IAM account access key and smtp password for SES.
  Assumes postfix has been previously configured and will be used for sending email via SES.
  Options:
  -h  Display this message.
  -A  Email address of the admin to which to send successful rotation email.
  -D  Domain from which to send successful rotation email.
  -U  IAM Username used for sending email via SES, access keys will be rotated.
EOT
}  # ----------  end of function usage  ----------

# Parse command-line parameters
while getopts :hA:D:U: opt
do
    case "${opt}" in
        h)
            usage
            exit 0
            ;;
        A)
            ADMIN_EMAIL_ADDRESS="${OPTARG}"
            ;;
        D)
            MAIL_FROM_DOMAIN="${OPTARG}"
            ;;
        U)
            IAM_USERNAME="${OPTARG}"
            ;;
        \?)
            usage
            echo "ERROR: unknown parameter \"$OPTARG\""
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# Validate parameters
if [ -z "${ADMIN_EMAIL_ADDRESS}" ]
then
  die "Admin Email Address (-A) was not provided; exiting"
fi

if [ -z "${MAIL_FROM_DOMAIN}" ]
then
  die "Domain from which to send successful email (-D) was not provided; exiting"
fi

if [ -z "${IAM_USERNAME}" ]
then
  die "IAM Username (-U) was not provided; exiting"
fi

log "Begin execution of ses rotate script on ${HOSTNAME}"

yum -y install epel-release
yum-config-manager --enable epel
yum -y install jq mutt postfix wget cyrus-sasl-plain

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
  printf "[email-smtp.us-east-1.amazonaws.com]:25 __AKID__:__US_EAST_1_SMTPPASSWORD__\n"
  printf "[email-smtp.us-east-1.amazonaws.com]:587 __AKID__:__US_EAST_1_SMTPPASSWORD__\n"
  printf "\n"
  printf "# SES us-west-2\n"
  printf "[email-smtp.us-west-2.amazonaws.com]:25 __AKID__:__US_WEST_2_SMTPPASSWORD__\n"
  printf "[email-smtp.us-west-2.amazonaws.com]:587 __AKID__:__US_WEST_2_SMTPPASSWORD__\n"
  printf "\n"
) > /usr/local/bin/sasl_passwd_template

#create .muttsesrotaterc
log "Create mutt config"
(
  printf "set realname=\"$MAIL_FROM_DOMAIN SES Rotate Script\"\n"
  printf "set from=\"sesrotate@$MAIL_FROM_DOMAIN\"\n"
  printf "set use_from = yes\n"
  printf "set edit_headers = yes\n"
  printf "set use_envelope_from = yes\n"
) > /root/.muttsesrotaterc

#create sescredrotatedemail
log "Create admin email template"
echo '<html><head></head><body>IAM access keys used for SES sending have been successfully rotated: <br><br>IAM Username: __IAMUSERNAME__, EC2 Instance ID: __EC2ID__, <br><br><br></body></html>' > /usr/local/bin/sescredrotatedemail.html

log "Get current access keys"
inactivestatus=Inactive
currentkeys=$(aws iam list-access-keys --user-name $IAM_USERNAME)
if [ $? -ne 0 ]
then
      die "Unable to query for IAM user access keys"
fi
#check key count
keycount=$(jq -r '.AccessKeyMetadata | length' <<< $currentkeys)
#if 2 keys exist for user, delete inactive or oldest key
log "${IAM_USERNAME} currently has ${keycount} access keys"
if [ $keycount == 2 ]
then
  #find and delete inactive key
  for (( c=0; c<$keycount; c++ ))
  do 
    thiskey=$(jq -r .AccessKeyMetadata[$c] <<< $currentkeys)
    thiskeystatus=$(jq -r .AccessKeyMetadata[$c].Status <<< $currentkeys)
    thiskeydate=$(jq -r .AccessKeyMetadata[$c].CreateDate <<< $currentkeys)
    if [ $thiskeystatus == $inactivestatus ]
    then
      log "One key is inactive, deleting inactive key (Created: ${thiskeydate})..."
      #delete inactive key
      thiskeyid=$(jq -r .AccessKeyId <<< $thiskey)
      aws iam delete-access-key --user-name $IAM_USERNAME --access-key-id $thiskeyid
    fi
  done
  currentkeys=$(aws iam list-access-keys --user-name $IAM_USERNAME)
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
      log "key0 (Created: ${key0date}) is older than key1 (Created: ${key1date}), deleting key0..."
      key0id=$(jq -r .AccessKeyMetadata[0].AccessKeyId <<< $currentkeys)
      aws iam delete-access-key --user-name $IAM_USERNAME --access-key-id $key0id
    else 
      log "key1 (Created: ${key1date}) is older than key0 (Created: ${key1date}), deleting key1..."
      key1id=$(jq -r .AccessKeyMetadata[1].AccessKeyId <<< $currentkeys)
      aws iam delete-access-key --user-name $IAM_USERNAME --access-key-id $key1id
    fi
  fi
fi
#check key count again just for verification
currentkeys=$(aws iam list-access-keys --user-name $IAM_USERNAME)
keycount=$(jq -r '.AccessKeyMetadata | length' <<< $currentkeys)
#creat new key, new sasl_passwd contents, send test email, and set old key to inactive
if [ $keycount -lt 2 ]
then 
  log "Less than 2 access keys, creating new key..."
  existingkey=$(aws iam list-access-keys --user-name $IAM_USERNAME)
  existingkeyid=$(jq -r .AccessKeyMetadata[0].AccessKeyId <<< $existingkey)
  #create new key and secret
  newkey=$(aws iam create-access-key --user-name $IAM_USERNAME)
  newkeyid=$(jq -r .AccessKey.AccessKeyId <<< $newkey)
  newkeysecret=$(jq -r .AccessKey.SecretAccessKey <<< $newkey)
  #create smtp password from secret
  log "Converting secret to smtp_password..."
  US_EAST_1_SMTP_PASSWORD=$(python3 /usr/local/bin/key2smtppass.py --secret $newkeysecret --region us-east-1)
  US_WEST_2_SMTP_PASSWORD=$(python3 /usr/local/bin/key2smtppass.py --secret $newkeysecret --region us-west-2)
  #copy sasl_passwd template and adjust contents
  log "Copy sasl_passwd_template..."
  cp -rf /usr/local/bin/sasl_passwd_template /etc/postfix/sasl_passwd
  log "Adjust new sasl_passwd..."
  /usr/bin/sed -i \
    -e "s|__AKID__|$newkeyid|" \
    -e "s|__US_EAST_1_SMTPPASSWORD__|$US_EAST_1_SMTP_PASSWORD|" \
    -e "s|__US_WEST_2_SMTPPASSWORD__|$US_WEST_2_SMTP_PASSWORD|" \
  /etc/postfix/sasl_passwd
  now=$(date -d "today" +"%Y.%m.%d %H:%M:%S")
  nowcomment="#Modified ${now}"
  echo $nowcomment >> /etc/postfix/sasl_passwd
  #use new creds
  log "Use new sasl_passwd..."
  service postfix restart
  /sbin/postmap /etc/postfix/sasl_passwd
  log "Sleep for 10s... (test, initial email w/o sleep w new creds failed)"
  sleep 10
  #add instance id and ses iam username to email
  log "Get ec2 instance id..."
  ec2id="`wget -q -O - http://169.254.169.254/latest/meta-data/instance-id || die \"wget instance-id has failed: $?\"`"
  log "Adjust email template..."
  /usr/bin/sed -i \
    -e "s|__IAMUSERNAME__|$IAM_USERNAME|" \
    -e "s|__EC2ID__|$ec2id|" \
  /usr/local/bin/sescredrotatedemail.html
  #send test email to admin
  log "Send admin email using new creds..."
  mutt -F /root/.muttsesrotaterc -e 'set content_type=text/html' -s "SES Credential Rotated" $ADMIN_EMAIL_ADDRESS < /usr/local/bin/sescredrotatedemail.html
  sleep 5
  if [[ $(mailq | grep -c "^[A-F0-9]") -eq 0 ]]
  then 
    log "Mail queue empty, Test email sent, Make old access key inactive..."
    aws iam update-access-key --user-name $IAM_USERNAME --access-key-id $existingkeyid --status $inactivestatus
  else 
    die "SES credential problem - mail stuck in queue"
  fi
  log "Created new key..."
fi 
log "Done..."