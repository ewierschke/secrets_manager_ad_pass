#place script in /usr/local/bin
#create entry in /etc/crontab
#*/10 * * * * root /usr/local/bin/ParameterKMSDecryptinlast10min.sh

REGION="us-east-1"
#what secret/resource name to look for
resourcename="my/secret/name"

yum -y install epel-release
yum-config-manager --enable epel
yum -y install jq mutt postfix

#get all Decrypt events from the last 10 minutes in the region where my secret resides
nowformatted=$(date "+%s")
nowminustenminformatted=$(date --date '-10 minutes' "+%s")
events=$(aws cloudtrail lookup-events --region ${REGION} --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt --start-time ${nowminustenminformatted} --end-time ${nowformatted})

#get yesterdays Decrypt events for log file
yesterdaydate=$(date --date '-1 day' "+%D")
yesterdaylogname=/var/log/$(date +%F --date $yesterdaydate)-Decrypt-Events.log
if [ ! -f "$yesterdaylogname" ]; then
    yesterday=$(date --date '-1 day' "+%s")
    yesterdayendofday=$(date --date '+24 hours' "+%s")
    #twodaysago=$(date --date '-2 day' "+%D")
    yesterdaysevents=$(aws cloudtrail lookup-events --region ${REGION} --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt --start-time ${yesterday} --end-time ${yesterdayendofday})
    echo $yesterdaysevents >> $yesterdaylogname
fi

#get number of events
eventcount=$(jq -r '.Events | length' <<< $events)
echo "${eventcount} Decrypt events occurred in the time period"

#loop through event index searching for resource name
emails=0
for (( c=0; c<$eventcount; c++ ))
do
    thiseventresourcename=$(jq .[] <<< $events | jq -r .[$c].CloudTrailEvent | jq .requestParameters.encryptionContext.PARAMETER_ARN)
    if [ $thiseventresourcename == *"$resourcename"* ]
    then
        #get event details to send in email
        thisevent=$(jq .[] <<< $events | jq -r .[$c].CloudTrailEvent)
        #things to send
        __principalId__=$(jq -r .userIdentity.principalId <<< $thisevent)
        __arn__=$(jq -r .userIdentity.arn <<< $thisevent)
        __userIdentity__=$(jq -r .userIdentity <<< $thisevent)
        __eventTime__=$(jq -r .eventTime <<< $thisevent)
        __eventName__=$(jq -r .eventName <<< $thisevent)
        __PARAMETERARN__=$(jq -r .requestParameters.encryptionContext.PARAMETER_ARN <<< $thisevent)
        #send email
        echo "Your SSM Parameter Store SecureString Value was viewed at ${__eventTime__} by ${__arn__}"
        cp /usr/local/bin/emailsniporigssmparam.html /usr/local/bin/emailsnip$c.html
        #sed -i "s~__principalId__~$__principalId__~g" /usr/local/bin/emailsnip$c.html
        sed -i "s~__arn__~$__arn__~g" /usr/local/bin/emailsnip$c.html
        #sed -i "s~__userIdentity__~$__userIdentity__~g" /usr/local/bin/emailsnip$c.html
        sed -i "s~__eventTime__~$__eventTime__~g" /usr/local/bin/emailsnip$c.html
        sed -i "s~__eventName__~$__eventName__~g" /usr/local/bin/emailsnip$c.html
        sed -i "s~__resourcename__~${resourcename}~g" /usr/local/bin/emailsnip$c.html
        rm -rf /usr/local/bin/fullemail.html
        cat /usr/local/bin/emailpart1.html /usr/local/bin/emailsnip$c.html /usr/local/bin/emailpart2.html > /usr/local/bin/fullemail.html
        envirname=$(cat /usr/local/bin/envirname)
        mailtoaddress=$(cat /usr/local/bin/mailtoaddress)
        mailfromdomain=$(cat /usr/local/bin/mailfromdomain)
        mutt -F /root/.muttrc -e 'set content_type=text/html' -s "SSM Parameter Store SecureString Value was viewed!" $mailtoaddress < /usr/local/bin/fullemail.html
        #cleanup
        shred -u /usr/local/bin/fullemail.html
        shred -u /usr/local/bin/emailsnip$c.html
        emails++
    else 
        echo "Decrypt event ${c} did not relate to ${resourcename}"
    fi
done
echo "There were ${emails} Decrypt events relating to ${resourcename} in the time period"
