#!/usr/bin/env python

#Version 1.4

#Changelog:

#Version 1.0
#Initial Release

#Version 1.1
#Added check for major version number
#Improved hardening descriptions
#Added MPTCP block for PAN-OS 8.0+

#Version 1.2
#Added UTC timezone and NTP configuration
#Added minimum password complexity
#Added idle timeout
#Added high DP load logging
#Added verify update server identity
#Added asterisk bars to output to help separate sections

#Version 1.3
#Added login banner and CIS references
#Changed HTTP response code sig generation to a loop to make it easier to add response signatures
#Added a threat signature for every common HTTP response status
#Separated content updates from content update scheduling

#Version 1.4
#Moved master key change to the beginning of the script to avoid creating uncommitted changes

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as ET

#Input ip/username/password
print "*****************************************************************************"
fwip = raw_input("IP: ")
username = raw_input("Username: ")
password = raw_input("Password: ")

#Generate API key
call = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwip,username,password)
try:
	r = requests.get(call, verify=False)
	tree = ET.fromstring(r.text)
	if tree.get('status') == "success":
		fwkey = tree[0][0].text

except requests.exceptions.ConnectionError as e:
	print "There was a problem connecting to the firewall.  Please check the connection information and try again."

try:
	fwkey
except NameError as e:
	print "There was a problem connecting to the firewall.  Please check the connection information and try again."
else:

	#Get PAN-OS version
	type = "op"
	cmd = "<show><system><info></info></system></show>"
        call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
        r = requests.get(call, verify=False)
        tree = ET.fromstring(r.text)
        version = int(tree[0][0].find('sw-version').text.split(".")[0])

        print "*****************************************************************************"
        #Check to see if master key has been set
        type = "op"
        cmd = "<show><system><masterkey-properties/></system></show>"
        call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
        r = requests.get(call, verify=False)
        tree = ET.fromstring(r.text)
        if tree[0][2].text == "0" and tree[0][3].text == "0" and tree[0][4].text == "0":
                resetkey = raw_input("The master key is still set to the default.  Would you like to change it now? [y/n]: ")
                if resetkey == "y" or resetkey =="Y":
                        #Set master key
                        masterkey = raw_input("New Master Key (16 characters): ")
                        type = "op"
                        cmd = "<request><master-key><new-master-key>%s</new-master-key><lifetime>17520</lifetime></master-key></request>" % (masterkey)
                        call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
                        r = requests.get(call, verify=False)
                        tree = ET.fromstring(r.text)
                        print "Set master key: " + tree.get('status') + " - " + str(tree[0].text)
        else:
                print "The master key has already been changed."

	print "*****************************************************************************"
	timeset = raw_input("Would you like to set the timezone to UTC and configure NTP? [y/n]: ")
	if timeset == "y" or timeset == "Y":

		#Set timezone to UTC
		type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
                element = "<timezone>UTC</timezone>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print "Set timezone to UTC: " + tree.get('status') + " - " + str(tree[0].text)

		#Set NTP servers configuration (CIS 1.6.2)
		type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ntp-servers"
                element = "<primary-ntp-server><ntp-server-address>wwv.nist.gov</ntp-server-address><authentication-type><none/></authentication-type></primary-ntp-server>"
		element += "<secondary-ntp-server><ntp-server-address>time.nist.gov</ntp-server-address><authentication-type><none/></authentication-type></secondary-ntp-server>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print "Configure redundant NTP servers (CIS 1.6.2): " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	hardenbuffers = raw_input("Would you like to prevent buffer overflow and multi-stream evasions? [y/n]: ")
	if hardenbuffers == "y" or hardenbuffers == "Y":

		#Harden CTD
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/ctd"
		element = "<skip-block-http-range>no</skip-block-http-range>"
		element += "<tcp-bypass-exceed-queue>no</tcp-bypass-exceed-queue>"
		element += "<udp-bypass-exceed-queue>no</udp-bypass-exceed-queue>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Prevent TCP and UDP buffer overflow and multi-part HTTP download evasions: " + tree.get('status') + " - " + str(tree[0].text)

		#Harden TCP
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/tcp"
		element = "<urgent-data>clear</urgent-data>"
		element += "<drop-zero-flag>yes</drop-zero-flag>"
		element += "<bypass-exceed-oo-queue>no</bypass-exceed-oo-queue>"
		element += "<check-timestamp-option>yes</check-timestamp-option>"
		if version > 7:
			element += "<strip-mptcp-option>yes</strip-mptcp-option>"
		else:
			print "Blocking MPTCP is not available on versions of PAN-OS prior to 8.0"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Prevent TCP and MPTCP evasions: " + tree.get('status') + " - " + str(tree[0].text)

		#Harden Application
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/application"
		element = "<bypass-exceed-queue>no</bypass-exceed-queue>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Prevent App-ID buffer overflow evasion: " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	dislogsup = raw_input("Would you like to disable log suppression? [y/n]: ")
        if dislogsup == "y" or dislogsup == "Y":

		#Disable Log Suppression
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/logging"
		element = "<log-suppression>no</log-suppression>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Disable Log Suppression: " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	defaultpolicies = raw_input("Would you like to set the deafult interzone and intrazone policies to drop and log? [y/n]: ")
	if defaultpolicies == "y" or defaultpolicies == "Y":

		#Set default interzone and intrazone policies to drop and log at session end (CIS 7.3)
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/default-security-rules/rules/entry[@name='interzone-default']"
		element = "<action>drop</action><log-end>yes</log-end>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Set interzone-default rule to drop and log at session end (CIS 7.3): " + tree.get('status') + " - " + str(tree[0].text)

		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/default-security-rules/rules/entry[@name='intrazone-default']"
		element = "<action>drop</action><log-end>yes</log-end>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Set intrazone-default rule to drop and log at session end (CIS 7.3): " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	contentupdate= raw_input("Would you like to download and install the latest dynamic content updates? [y/n]: ")
	if contentupdate =="y" or contentupdate =="Y":

		#download latest anti-virus update
		type = "op"
		cmd = "<request><anti-virus><upgrade><download><latest></latest></download></upgrade></anti-virus></request>"
		call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Download latest Anti-Virus update - " + str(jobid)

		completed = 0
		while (completed == 0):
			call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
		        r = requests.get(call, verify=False)
		        tree = ET.fromstring(r.text)
		        if (tree[0][0][5].text == 'FIN'):
				print "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                completed = 1
		        else:
		                status = "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                print '{0}\r'.format(status),

		#install latest anti-virus update without committing
		type = "op"
		cmd = "<request><anti-virus><upgrade><install><version>latest</version><commit>no</commit></install></upgrade></anti-virus></request>"
		call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Install latest Anti-Virus update - " + str(jobid)

		completed = 0
		while (completed == 0):
		        call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
		        r = requests.get(call, verify=False)
		        tree = ET.fromstring(r.text)
		        if (tree[0][0][5].text == 'FIN'):
		                print "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                completed = 1
		        else:
		                status = "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                print '{0}\r'.format(status),

		#Download latest applications and threats
		type = "op"
		cmd = "<request><content><upgrade><download><latest></latest></download></upgrade></content></request>"
		call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Download latest Applications and Threats update - " + str(jobid)

		completed = 0
		while (completed == 0):
		        call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
		        r = requests.get(call, verify=False)
		        tree = ET.fromstring(r.text)
		        if (tree[0][0][5].text == 'FIN'):
		                print "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                completed = 1
		        else:
		                status = "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                print '{0}\r'.format(status),

		#Install latest applications and threats without committing
		type = "op"
		cmd = "<request><content><upgrade><install><version>latest</version><commit>no</commit></install></upgrade></content></request>"
		call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Install latest Applications and Threats update - " + str(jobid)

		completed = 0
		while (completed == 0):
		        call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
		        r = requests.get(call, verify=False)
		        tree = ET.fromstring(r.text)
		        if (tree[0][0][5].text == 'FIN'):
		                print "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                completed = 1
		        else:
		                status = "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                print '{0}\r'.format(status),

		#Download latest WildFire update
		type = "op"
		cmd = "<request><wildfire><upgrade><download><latest></latest></download></upgrade></wildfire></request>"
		call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Download latest WildFire update - " + str(jobid)

		completed = 0
		while (completed == 0):
		        call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
		        r = requests.get(call, verify=False)
		        tree = ET.fromstring(r.text)
		        if (tree[0][0][5].text == 'FIN'):
		                print "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                completed = 1
		        else:
		                status = "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
                print '{0}\r'.format(status),

		#Install latest WildFire update without committing
		type = "op"
		cmd = "<request><wildfire><upgrade><install><version>latest</version><commit>no</commit></install></upgrade></wildfire></request>"
		call = "https://%s/api/?type=%s&cmd=%s&key=%s" % (fwip, type, cmd, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Install latest WildFire update - " + str(jobid)

		completed = 0
		while (completed == 0):
		        call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
		        r = requests.get(call, verify=False)
		        tree = ET.fromstring(r.text)
		        if (tree[0][0][5].text == 'FIN'):
		                print "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                completed = 1
		        else:
		                status = "Status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
		                print '{0}\r'.format(status),


        print "*****************************************************************************"
        schedulecontent = raw_input("Would you like to schedule recurring content updates? [y/n]: ")
        if schedulecontent == "y" or schedulecontent == "Y":

                #Set Anti-Virus to update every hour at 4 minutes past (CIS 4.1)
                type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/anti-virus/recurring"
                element = "<hourly><at>4</at><action>download-and-install</action></hourly>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print "Set Anti-Virus to download and install updates every hour at 4 minutes past (CIS 4.1): " + tree.get('status') + " - " + str(tree[0].text)

                #Set applications and threats to update every 30 minutes at 2 minutes past (Exceeds CIS 4.2)
                type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/threats/recurring"
                element = "<every-30-mins><action>download-and-install</action><at>2</at></every-30-mins>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print "Set Applications and Threats to download and install updates every 30 minutes at 2 minutes past (Exceeds CIS 4.2): " + tree.get('status') + " - " + str(tree[0].text)

                #Set WildFire update schedule to download and install every minute (Exceeds CIS 5.7)
                type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule/wildfire/recurring"
                element = "<every-min><action>download-and-install</action></every-min>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print "Set WildFire to download and install updates every minute (Exceeds CIS 5.7): " + tree.get('status') + " - " + str(tree[0].text)


	print "*****************************************************************************"
	createurl = raw_input("Would you like to create an alert-all URL filtering profile? [y/n]: ")
	if createurl == "y" or createurl == "Y":

		#Create URL filtering profile called 'alert-all'
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering"
		element = "<entry name='alert-all'/>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Create alert-all URL filtering profile: " + tree.get('status') + " - " + str(tree[0].text)

		#Set action for block list and generate maximum URL log verbosity (CIS 6.12)
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering/entry[@name='alert-all']"
		element = "<log-http-hdr-xff>yes</log-http-hdr-xff>"
		element += "<log-http-hdr-user-agent>yes</log-http-hdr-user-agent>"
		element += "<log-http-hdr-referer>yes</log-http-hdr-referer>"
		element += "<log-container-page-only>no</log-container-page-only>"
		element += "<action>block</action>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Configure alert-all profile to generate maximum log information (CIS 6.12): " + tree.get('status') + " - " + str(tree[0].text)

		#get URL categories
		categories = []

		type = "config"
		action = "get"
		xpath = "/config/predefined/pan-url-categories"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&key=%s" % (fwip, type, action, xpath, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		for element in tree[0]:
		        entries = element.findall('entry')
		        for entry in entries:
		                category = entry.get('name')
		                categories.append (str(category))

		#Add all categories to alert for 'alert-all' (CIS 6.11)
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/url-filtering/entry[@name='alert-all']/alert"
		element = ""
		for category in categories:
			element += "<member>%s</member>" % (category)
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Alert on all categories (CIS 6.11): " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	threatsigs = raw_input("Would you like to create threat signatures for HTTP response codes? [y/n]: ")
	if threatsigs =="y" or threatsigs =="Y":

		responsecodes = [ "100", "101", "102", "200", "201", "202", "203", "204", "205", "206", "207", "208", "226", "300", 
			"301", "302", "303", "304", "305", "306", "307", "308", "400", "401", "402", "403", "404", "405", "406", "407", 
			"408", "409", "410", "411", "412", "413", "414", "415", "416", "417", "421", "422", "423", "424", "426", "428", 
			"429", "431", "451", "500", "501", "502", "503", "504", "505", "506", "507", "508", "510", "511" ]
		threatid = 41000
		for responsecode in responsecodes:

			#Create Custom Threat Signatures
			type = "config"
			action = "set"
			xpath = "/config/shared/threats/vulnerability"
			element = '<entry name="%s"><signature><standard><entry name="HTTP-%s"><and-condition><entry name="And Condition 1">' % (threatid, responsecode)
			element += '<or-condition><entry name="Or Condition 1"><operator><equal-to><value>%s</value><context>http-rsp-code</context>' % (responsecode)
			element += '</equal-to></operator></entry></or-condition></entry></and-condition><order-free>yes</order-free><scope>session</scope>'
			element += '</entry></standard></signature>'
			element += '<default-action><alert/></default-action>'
			element += '<threatname>HTTP-%s</threatname>' % (responsecode)
			element += '<severity>informational</severity>'
			element += '<direction>server2client</direction>'
			element += '<affected-host><client>yes</client></affected-host></entry>'
			call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
			r = requests.get(call, verify=False)
			tree = ET.fromstring(r.text)
			print "Create HTTP-" + responsecode + " threat signature: " + tree.get('status') + " - " + str(tree[0].text)
			threatid += 1

	print "*****************************************************************************"
	vulnprofile = raw_input("Would you like to create a threat profile that performs the default behavior for all signatures? [y/n]: ")
	if vulnprofile == "y" or vulnprofile == "Y":

		#Create alert-all vulnerability profile (Exceeds CIS 6.7):
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/vulnerability"
		element = "<entry name='default-all'><rules><entry name='default-all'>"
		element += "<action><default/></action>"
		element += "<vendor-id><member>any</member></vendor-id>"
		element += "<severity><member>any</member></severity>"
		element += "<cve><member>any</member></cve>"
		element += "<threat-name>any</threat-name>"
		element += "<host>any</host>"
		element += "<category>any</category>"
		element += "<packet-capture>disable</packet-capture>"
		element += "</entry></rules></entry>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print  "Create default-all vulnerability profile (Exceeds CIS 6.7): " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	cisharden = raw_input("Would you like to configure additional CIS Benchmark recommendations? [y/n]: ")
	if cisharden == "y" or cisharden == "Y":

		#Set login banner (CIS 1.1.1)
		type = "config"
		action = "set"
		xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
		element = "<login-banner>You have accesses a protected system.  Log off immediately if you are not an authorized user.</login-banner>"
		call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		print "Set login banner (CIS 1.1.1): " + str(tree[0].text)

		#Password complexity (CIS 1.3)
		type = "config"
                action = "set"
                xpath = "/config/mgt-config/password-complexity"
                element = "<minimum-length>12</minimum-length>"
		element += "<minimum-uppercase-letters>1</minimum-uppercase-letters>"
		element += "<password-history-count>24</password-history-count>"
		element += "<minimum-lowercase-letters>1</minimum-lowercase-letters>"
		element += "<minimum-numeric-letters>1</minimum-numeric-letters>"
		element += "<minimum-special-characters>1</minimum-special-characters>"
		element += "<block-username-inclusion>yes</block-username-inclusion>"
		element += "<new-password-differs-by-characters>3</new-password-differs-by-characters>"
		element += "<enabled>yes</enabled>"
		element += "<password-change><expiration-period>90</expiration-period></password-change>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print  "Configure and enable password complexity (CIS 1.3): " + tree.get('status') + " - " + str(tree[0].text)

		#Management - Idle timeout (CIS 1.4.1) and log on high DP load (CIS 1.1.2)
                type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/management"
		element = "<idle-timeout>10</idle-timeout><enable-log-high-dp-load>yes</enable-log-high-dp-load>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print  "Set idle timeout to 10 minutes (CIS 1.4.1) and enable high DP load logging (CIS 1.1.2): " + tree.get('status') + " - " + str(tree[0].text)

		#Account lockout settings (CIS 1.4.2)
		type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/management/admin-lockout"
                element = "<failed-attempts>5</failed-attempts><lockout-time>10</lockout-time>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print  "Set admin lockout after 5 tries and lockout time to 10 minutes (CIS 1.4.2): " + tree.get('status') + " - " + str(tree[0].text)

		#Verify update server identity (CIS 1.6)
                type = "config"
                action = "set"
                xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
                element = "<server-verification>yes</server-verification>"
                call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (fwip, type, action, xpath, element, fwkey)
                r = requests.get(call, verify=False)
                tree = ET.fromstring(r.text)
                print  "Set verify update server identity (CIS 1.6): " + tree.get('status') + " - " + str(tree[0].text)

	print "*****************************************************************************"
	commit = raw_input("Would you like to commit these changes? [y/n]: ")
        if commit == "y" or commit == "Y":

		#Commit and monitor commit job for completion
		call = "https://%s/api/?type=commit&cmd=<commit><force></force></commit>&key=%s" % (fwip, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		jobid = tree[0][1].text
		print "Commit job - " + str(jobid)

		committed = 0
		while (committed == 0):
			call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (fwip, jobid, fwkey)
			r = requests.get(call, verify=False)
			tree = ET.fromstring(r.text)
			if (tree[0][0][5].text == 'FIN'):
				print "Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
				committed = 1
			else:
				status = "Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
				print '{0}\r'.format(status),
	else:
		print "The changes have been made to the candidate configuration, but have not been committed."
