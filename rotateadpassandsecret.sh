REGION="us-east-1"
USERNAME="my_account"
DOMAIN="example.com"
SECRET_ID="my/secret/name"
SECRET_KEY="mytestsecret"

yum -y install epel-release
yum-config-manager --enable epel
yum -y install jq

#get secret value
secret=$(aws secretsmanager get-secret-value --secret-id ${SECRET_ID} --region ${REGION})
valuepair=$(jq -r .SecretString <<< ${secret})
value=$(jq .[] <<< ${valuepair})
valuenoquotes=$(sed -e 's/^"//' -e 's/"$//' <<<"$value")
oldpassword=${valuenoquotes}

#create new random 16 char password
newpassword=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' | fold -w 16 | grep -i '[!@#$%^&*()_+{}|:<>?=]' | head -n 1)

#change password
(echo ${oldpassword}; echo ${newpassword}; echo ${newpassword}) | smbpasswd -s -U ${USERNAME} -r `nslookup _ldap._tcp.dc._msdcs.${DOMAIN} | awk '{print $2;exit;}'`
##need to test for success

#set secret value
testpassjson='{"'${SECRET_KEY}'":"'${newpassword}'"}'
aws secretsmanager put-secret-value --secret-id ${SECRET_ID} --region us-east-1 --secret-string ${testpassjson} --version-stages AWSCURRENT
##need to test for success