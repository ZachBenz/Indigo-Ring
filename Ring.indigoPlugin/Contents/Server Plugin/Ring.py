# Embedded file name: /Library/Application Support/Perceptive Automation/Indigo 7/Plugins/Ring.indigoPlugin/Contents/Server Plugin/Ring.py
try:
    import json
except:
    import simplejson as json

import os
import sys
pypath = os.path.realpath(sys.path[0])
sys.path.append(pypath)
try:
    import indigo
except:
    self.plugin.debugLog('This plugin must be run from inside Indigo 7.0')
    sys.exit(0)

import time
from datetime import datetime, tzinfo, timedelta
import logging
import requests
import socket
import sys
import urllib
import urllib2
import base64
import uuid
from applicationinsights import TelemetryClient
AUTH_REFRESH_TIMEOUT = 86400
TelemetryClientKey = '48d8185d-556d-4876-a6f3-ffaca58195f6'

class Ring(object):
    baseUrl = 'https://api.ring.com/clients_api/'
    headers = {'content-type': 'application/json',
     'User-Agent': 'ring/3.6.4 (iPhone; iOS 10.2; Scale/2.00)'}
    offset = datetime.utcnow() - datetime.now()
    requests.packages.urllib3.disable_warnings()

    def __init__(self, plugin):
        self.plugin = plugin
        self._last_auth_refresh = None
        self.sessionID = None
        self.authToken = None
        self.authTokenType = None
        self.timeFormat = None
        is_dst = time.daylight and time.localtime().tm_isdst > 0
        self.utc_offset = -(time.altzone if is_dst else time.timezone) * -1
        self.logTrace('Init', {'hostname': socket.gethostname()})
        self.hasSubscription = False
        return

    def __del__(self):
        pass

    def startTelemetry(self):
        self.plugin.debugLog('Starting Telemetry')
        self.tc = TelemetryClient(TelemetryClientKey)
        self.tc.context.device.model = 'Ring'
        self.tc.context.application.ver = self.plugin.pluginVersion
        self.tc.channel.sender.send_interval_in_milliseconds = 30000
        self.tc.channel.sender.max_queue_item_count = 10

    def startup(self, force):
        logging.getLogger('requests').setLevel(logging.WARNING)
        if self.plugin.pluginPrefs.get('sendTelemetry', False):
            self.plugin.debugLog('Telemetry enabled')
            self.startTelemetry()
        else:
            self.plugin.debugLog('Telemetry disabled')
        result = self.refreshAuth(force)
        return result

    def refreshAuth(self, force):
        if force == True:
            self.plugin.debugLog('Forcing re-Login!')
            self.sessionID = None
            self._last_auth_refresh == None
        if self._last_auth_refresh is None or time.time() - self._last_auth_refresh > AUTH_REFRESH_TIMEOUT:
            if self._last_auth_refresh is not None:
                self.plugin.debugLog('_last_auth_refresh age is %s.  Requesting new one.' % (time.time() - self._last_auth_refresh))
            else:
                self.plugin.debugLog('Will Authenticate')
            loginResult = self.getOauthToken(self.plugin.pluginPrefs['UserID'], self.plugin.pluginPrefs['Password'])
            if loginResult == True:
                self._last_auth_refresh = 1
                return True
            else:
                return False
        return

    def getOauthToken(self, username, password):
        self.plugin.debugLog('Getting Oauth Token')
        url = 'https://oauth.ring.com/oauth/token'
        request = urllib2.Request(url)
        base64string = base64.b64encode('%s:%s' % (username, password))
        request.add_header('content-type', 'application/json')
        request.add_header('User-Agent', 'ring/4.1.18 (iPhone; iOS 11.4; Scale/2.00)')
        loginData = {'username': username,
         'password': password,
         'client_id': 'ring_official_ios',
         'scope': 'client',
         'grant_type': 'password'}
        try:
            result = urllib2.urlopen(request, json.dumps(loginData))
        except urllib2.HTTPError as err:
            if err.code == 401 or err.code == 403:
                self.plugin.debugLog('Login failed! Check your username/password.')
                return False

        if result.getcode() != 200:
            self.plugin.debugLog('Login failed! Check your username/password.')
            return False
        content = json.loads(result.read())
        authToken = content['access_token']
        authTokenType = content['token_type']
        return self.getSession(authToken, authTokenType)

    def getSession(self, token, token_type):
        self.plugin.debugLog('Getting Session Id')
        url = self.baseUrl + 'session'
        request = urllib2.Request(url)
        request.add_header('Authorization', '%s %s' % (token_type, token))
        request.add_header('content-type', 'application/json')
        request.add_header('User-Agent', 'ring/4.1.18 (iPhone; iOS 11.4; Scale/2.00)')
        metadata = {'app_version': '123',
         'api_version': '8',
         'language': 'en'}
        devicedata = {'os': 'ios',
         'app_brand': 'ring',
         'hardware_id': str(uuid.uuid1()),
         'metadata': metadata}
        postdata = {'device': devicedata}
        try:
            result = urllib2.urlopen(request, json.dumps(postdata))
        except urllib2.HTTPError as err:
            if err.code == 401 or err.code == 403:
                self.plugin.debugLog('Login failed! Check your username/password.')
            else:
                self.plugin.debugLog('Failed to login.  Network error.')
            return False

        if result.getcode() != 201:
            self.plugin.debugLog('Login failed! Check your username/password.')
            return False
        content = json.loads(result.read())
        self.sessionID = content['profile']['authentication_token']
        self._last_auth_refresh = time.time()
        self.GetProfileSettings()
        return True

    def GetProfileSettings(self):
        url = self.baseUrl + 'profile?api_version=8&auth_token=' + self.sessionID
        response = requests.get(url, headers=self.headers, verify=False)
        if response.status_code == 200:
            content = json.loads(response.content)
            feature_subscriptions = content['profile']['features']['subscriptions_enabled']
            feature_ringPlus = content['profile']['features']['ringplus_enabled']
            self.hasSubscription = bool(feature_subscriptions)

    def GetDevice(self, doorbellId):
        url = self.baseUrl + 'ring_devices/' + doorbellId + '?api_version=9&auth_token=' + self.sessionID
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                content = json.loads(response.content)
                d = self.Doorbell()
                d.description = content['description']
                d.id = content['id']
                if content['battery_life'] is not None:
                    d.batterylevel = int(content['battery_life'])
                d.kind = content['kind']
                d.firmware_version = content['firmware_version']
                return d
        except requests.exceptions.ConnectionError:
            self.plugin.errorLog(u'Connection was refused.  Could be a network error.')
            return

        return

    def GetDevices(self):
        if not self.sessionID:
            self.plugin.errorLog(u'Did not have valid sessionID')
        url = self.baseUrl + 'ring_devices?api_version=9&auth_token=' + self.sessionID
        self.logTrace('GetDevices', {'url': url})
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            if response.status_code == 200:
                Devices = {}
                content = json.loads(response.content)
                for x in content['doorbots']:
                    d = self.Doorbell()
                    d.description = x['description']
                    d.id = x['id']
                    d.battery_life = x['battery_life']
                    d.kind = x['kind']
                    d.firmware_version = x['firmware_version']
                    d.batteryLevel = x['battery_life']
                    Devices[d.id] = d

                for x in content['authorized_doorbots']:
                    d = self.Doorbell()
                    d.description = x['description']
                    d.id = x['id']
                    d.battery_life = x['battery_life']
                    d.kind = x['kind']
                    d.firmware_version = x['firmware_version']
                    d.batteryLevel = x['battery_life']
                    Devices[d.id] = d

                for x in content['stickup_cams']:
                    d = self.Doorbell()
                    d.description = x['description']
                    d.id = x['id']
                    d.battery_life = x['battery_life']
                    d.kind = x['kind']
                    d.firmware_version = x['firmware_version']
                    d.batteryLevel = x['battery_life']
                    Devices[d.id] = d

                response = None
                return Devices
        except requests.exceptions.ConnectionError:
            self.plugin.errorLog(u'Failed to connect to ring.com system.  Network could be down.')
            return False

        return

    def GetDoorbellEvent(self):
        if self.sessionID is None:
            self.plugin.debugLog('Not authed.')
            return False
        else:
            Events = {}
            url = self.baseUrl + 'dings/active?api_version=8&auth_token=' + self.sessionID
            try:
                response = requests.get(url, headers=self.headers, verify=False)
                if response.status_code == 200:
                    content = json.loads(response.content)
                    content = json.loads(response.content)
                    for x in content:
                        e = self.Event()
                        e.description = x['doorbot_description']
                        e.id = x['id']
                        e.kind = x['kind']
                        e.motion = x['motion']
                        e.doorbot_id = x['doorbot_id']
                        e.state = x['state']
                        e.expires_in = x['expires_in']
                        e.answered = False
                        e.now = datetime.strptime(str(datetime.fromtimestamp(round(x['now']))), '%Y-%m-%d %H:%M:%S')
                        Events[e.id] = e

                return Events
            except requests.exceptions.ConnectionError:
                self.plugin.errorLog(u'Failed to connect to ring.com system.  Network could be down.')
                return False

            return

    def GetDoorbellEventsforId(self, doorbellId):
        url = self.baseUrl + 'doorbots/history?api_version=9&auth_token=' + self.sessionID + '&doorbot_ids%5B%5D=' + doorbellId + '&limit=1'
        response = requests.get(url, headers=self.headers, verify=False)
        if response.status_code == 200:
            content = json.loads(response.content)
            for x in content:
                e = self.Event()
                e.answered = x['answered']
                e.id = x['id']
                e.kind = x['kind']
                e.doorbot_id = x['doorbot']['id']
                e.description = x['doorbot']['description']
                utc = datetime.strptime(x['created_at'], '%Y-%m-%dT%H:%M:%S.000Z')
                localtime = utc - timedelta(seconds=self.utc_offset)
                e.now = localtime
                e.recordingState = x['recording']['status']
                return e

    def SetSirenOn(self, lightId):
        url = self.baseUrl + 'doorbots/' + lightId + '/siren_on'
        postdata = {'api_version': '9',
         'auth_token': self.sessionID}
        response = requests.put(url, data=json.dumps(postdata), headers=self.headers, verify=False)
        if response.status_code == 200:
            return True
        else:
            return False

    def SetSirenOff(self, lightId):
        url = self.baseUrl + 'doorbots/' + lightId + '/siren_off'
        postdata = {'api_version': '9',
         'auth_token': self.sessionID}
        response = requests.put(url, data=json.dumps(postdata), headers=self.headers, verify=False)
        if response.status_code == 200:
            return True
        else:
            return False

    def SetFloodLightOn(self, lightId):
        url = self.baseUrl + 'doorbots/' + lightId + '/floodlight_light_on'
        postdata = {'api_version': '9',
         'auth_token': self.sessionID}
        response = requests.put(url, data=json.dumps(postdata), headers=self.headers, verify=False)
        if response.status_code == 200:
            return True
        else:
            return False

    def SetFloodLightOff(self, lightId):
        url = self.baseUrl + 'doorbots/' + lightId + '/floodlight_light_off'
        postdata = {'api_version': '9',
         'auth_token': self.sessionID}
        response = requests.put(url, data=json.dumps(postdata), headers=self.headers, verify=False)
        if response.status_code == 200:
            return True
        else:
            return False

    def GetDoorbellEvents(self):
        url = self.baseUrl + 'doorbots/history?api_version=8&auth_token=' + self.sessionID + '&limit=30'
        response = requests.get(url, headers=self.headers, verify=False)
        if response.status_code == 200:
            content = json.loads(response.content)
            Events = {}
            content = json.loads(response.content)
            for x in content:
                e = self.Event()
                e.answered = x['answered']
                e.id = x['id']
                e.kind = x['kind']
                e.doorbot_id = x['doorbot']['id']
                e.description = x['doorbot']['description']
                utc = datetime.strptime(x['created_at'], '%Y-%m-%dT%H:%M:%S.000Z')
                localtime = utc - timedelta(seconds=self.utc_offset)
                e.now = localtime
                Events[e.id] = e

            return Events

    def GetRecordingUrl(self, recordingId):
        self.plugin.debugLog('Getting Recording URL for Event %s' % recordingId)
        if self.hasSubscription == False:
            self.plugin.debugLog('Subscription Disabled')
            return 'No Subscription'
        url = '%sdings/%s/recording?api_version=9&disable_redirect=false&auth_token=%s' % (self.baseUrl, recordingId, self.sessionID)
        self.plugin.debugLog('url: %s' % url)
        loopCount = 0
        self.plugin.debugLog('Loop: %s' % loopCount)
        while loopCount < 10:
            self.plugin.debugLog('Loop inner: %s' % loopCount)
            try:
                request = urllib2.Request(url)
                request.add_header('User-Agent', 'ring/4.1.8 (iPhone; iOS 11.2.5; Scale/2.00)')
                result = urllib2.urlopen(request)
                recordingUrl = result.geturl()
                self.plugin.debugLog('Event Url: %s' % recordingUrl)
                return recordingUrl
            except IOError as error:
                self.plugin.debugLog(u'Sleeping as we wait for file to be available')
                time.sleep(15)
                loopCount = loopCount + 1

    def logTrace(self, caller, trace):
        if self.plugin.pluginPrefs.get('sendTelemetry', False):
            try:
                self.tc
                if self.tc == None:
                    self.startTelemetry()
            except Exception as err:
                self.plugin.debugLog('Failed to send telemetry: %s' % err)
                self.startTelemetry()

            self.tc.track_trace(caller, trace)
            self.tc.flush()
        return

    def downloadVideo(self, dev, filename, eventId):
        try:
            if filename:
                if eventId == '':
                    self.plugin.errorLog(u"No Event ID specified to download for '%s'" % dev.name)
                    return
                url = self.GetRecordingUrl(eventId)
                if url == 'No Subscription':
                    self.plugin.errorLog(u'No valid subscription for download')
                    return
                response = requests.get(url, headers=self.headers, verify=False)
                if response and response.status_code == 200:
                    self.plugin.debugLog('200')
                    with open(filename, 'wb') as recording:
                        recording.write(response.content)
                        self.plugin.debugLog(u"Downloaded video of event for '%s' to %s" % (dev.name, filename))
                        return
                elif response:
                    self.plugin.errorLog(u"Failed to download for '%s', response status code was %s" % (dev.name, response.status_code))
                else:
                    self.plugin.errorLog(u"Failed to download for '%s', no response for url %s" % (dev.name, url))
            else:
                self.plugin.errorLog(u"Missing filename setting in action settings for video download of event for '%s'" % dev.name)
                return
        except IOError as error:
            self.plugin.errorLog(u'Exception: Error Downloading Video %s' % error)

    class Doorbell:
        id = None
        description = None
        battery_life = None
        kind = None
        firmware_version = None
        batteryLevel = None
        state = None

    class Event:
        id = None
        kind = None
        motion = None
        description = None
        doorbot_id = None
        now = None
        state = None
        expires_in = None
        answered = None
        recordingUrl = None
        recordingState = 'Not Ready'