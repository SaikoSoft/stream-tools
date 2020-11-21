#!/usr/bin/env python3

import argparse
import datetime
import dateutil.parser
from email.message import EmailMessage
import http.client
import httplib2
import logging
import os
import platform
import random
import re
import requests
import smtplib
import sys
import textwrap
import time
import traceback
from types import TracebackType
from typing import Collection, Dict, NamedTuple, Type

from apiclient.discovery import build, Resource
from apiclient.errors import HttpError
from apiclient.http import MediaFileUpload
from oauth2client.client import flow_from_clientsecrets, OAuth2Credentials
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow


if platform.system() == 'Windows':
    RECORDINGS_DIR = r'D:\Users\Tim\Videos\stream_recordings'
else:
    RECORDINGS_DIR = '/mnt/d/Users/Tim/Videos/stream_recordings'
ARCHIVE_DIR = os.path.join(RECORDINGS_DIR, 'archive')


THIS_SCRIPT = os.path.splitext(os.path.basename(__file__))[0]
LOG_FILE_NAME = f'{THIS_SCRIPT}_{datetime.datetime.now():%Y%m%d_%H%M%S}.log'
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler(sys.stdout))
log.addHandler(logging.FileHandler(os.path.join(RECORDINGS_DIR, 'logs', LOG_FILE_NAME)))


# Explicitly tell the underlying HTTP transport library not to retry, since we are handling retry logic ourselves.
httplib2.RETRIES = 1


def send_plaintext_email(subject: str, body: str, to: Collection[str], sender: str, password: str) -> None:
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ','.join(to)

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.ehlo()
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)


def on_uncaught_exception(exc_type: Type[BaseException], exc_value: BaseException, exc_traceback: TracebackType) -> None:
    # Default exception handler (print traceback to stderr)
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

    # Send error email
    password = open('email_password.txt').read().strip()
    msg = f"""
Uncaught {exc_type.__name__}: {exc_value}

{''.join(traceback.format_tb(exc_traceback))}
    """
    send_plaintext_email(
        subject=f'[{THIS_SCRIPT}] Uncaught {exc_type.__name__}',
        body=msg,
        to=['saikosoft.dev@gmail.com'],
        sender='saikosoft.dev@gmail.com',
        password=password,
    )
sys.excepthook = on_uncaught_exception


def get_oauth_credentials(
        service_name: str,
        secrets_file: str,
        scope: str,
        auth_server_args: argparse.Namespace,
) -> OAuth2Credentials:
    # The secrets_file variable specifies the name of a file that contains the OAuth 2.0 information for this
    # application, including its client_id and client_secret. You can acquire an OAuth 2.0 client ID and client secret from
    # the Google API Console at https://console.developers.google.com/.
    # Please ensure that you have enabled the YouTube Data API for your project.
    # For more information about using OAuth2 to access the YouTube Data API, see:
    #   https://developers.google.com/youtube/v3/guides/authentication
    # For more information about the client_secrets.json file format, see:
    #   https://developers.google.com/api-client-library/python/guide/aaa_client_secrets

    # This variable defines a message to display if the secrets_file is missing.
    MISSING_CLIENT_SECRETS_MESSAGE = textwrap.dedent(f"""
        WARNING: Please configure OAuth 2.0

        To make this sample run you will need to populate the {secrets_file} file
        found at:

        {os.path.abspath(os.path.join(os.path.dirname(__file__), secrets_file))}

        with information from the API Console
        https://console.developers.google.com/

        For more information about the client_secrets.json file format, please visit:
        https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
    """)

    storage = Storage(f'{THIS_SCRIPT}-{service_name}-oauth2.json')
    credentials = storage.get()

    if credentials is None or credentials.invalid:
        flow = flow_from_clientsecrets(secrets_file, scope=scope, message=MISSING_CLIENT_SECRETS_MESSAGE)
        credentials = run_flow(flow, storage, auth_server_args)

    return credentials


def get_authenticated_service(
        service_name: str,
        api_version: str,
        credentials: OAuth2Credentials
) -> Resource:
    return build(service_name, api_version, http=credentials.authorize(httplib2.Http()))


def initialize_upload(youtube, options):
    tags = None
    if options.keywords:
        tags = options.keywords.split(',')

    body = {
        'snippet': {
            'title': options.title,
            'description': options.description,
            'tags': tags,
            'categoryId': options.category,
        },
        'status': {
            'privacyStatus': options.privacyStatus,
        },
    }

    # Call the API's videos.insert method to create and upload the video.
    insert_request = youtube.videos().insert(
        part=','.join(body.keys()),
        body=body,
        # The chunksize parameter specifies the size of each chunk of data, in bytes, that will be uploaded at a time.
        # Set a higher value for reliable connections as fewer chunks lead to faster uploads. Set a lower value for
        # better recovery on less reliable connections.
        #
        # Setting 'chunksize' equal to -1 in the code below means that the entire file will be uploaded in a single HTTP
        # request. (If the upload fails, it will still be retried where it left off.) This is usually a best practice,
        # but if you're using Python older than 2.6 or if you're running on App Engine, you should set the chunksize to
        # something like 1024 * 1024 (1 megabyte).
        media_body=MediaFileUpload(options.file, chunksize=-1, resumable=True)
    )

    resumable_upload(insert_request)


# This method implements an exponential backoff strategy to resume a failed upload.
def resumable_upload(insert_request):
    # Maximum number of times to retry before giving up.
    MAX_RETRIES = 10

    # Always retry when these exceptions are raised.
    RETRIABLE_EXCEPTIONS = (httplib2.HttpLib2Error, IOError, http.client.NotConnected,
        http.client.IncompleteRead, http.client.ImproperConnectionState,
        http.client.CannotSendRequest, http.client.CannotSendHeader,
        http.client.ResponseNotReady, http.client.BadStatusLine)

    # Always retry when an apiclient.errors.HttpError with one of these status codes is raised.
    RETRIABLE_STATUS_CODES = [500, 502, 503, 504]

    response = None
    error = None
    retry = 0
    while response is None:
        try:
            log.info('Uploading file...')
            status, response = insert_request.next_chunk()
            if response is not None:
                if 'id' in response:
                    log.info(f'Video id "{response["id"]}" was successfully uploaded.')
                else:
                    sys.exit(f'The upload failed with an unexpected response: {response}')
        except HttpError as e:
            if e.resp.status in RETRIABLE_STATUS_CODES:
                error = f'A retriable HTTP error {e.resp.status} occurred:\n{e.content}'
            else:
                raise
        except RETRIABLE_EXCEPTIONS as e:
            error = f'A retriable error occurred: {e}'

        if error is not None:
            log.error(error)
            retry += 1
            if retry > MAX_RETRIES:
                sys.exit('No longer attempting to retry.')

            max_sleep = 2 ** retry
            sleep_seconds = random.random() * max_sleep
            log.info(f'Sleeping {sleep_seconds} seconds and then retrying...')
            time.sleep(sleep_seconds)


def parse_args() -> argparse.Namespace:
    VALID_PRIVACY_STATUSES = ('public', 'private', 'unlisted')

    argparser.add_argument('--file', required=True, help='Video file to upload')
    argparser.add_argument('--title', help='Video title', default='Test Title')
    argparser.add_argument('--description', default='Test Description', help='Video description')
    argparser.add_argument('--category', default='22',
                           help='Numeric video category. See https://developers.google.com/youtube/v3/docs/videoCategories/list')
    argparser.add_argument('--keywords', default='', help='Video keywords, comma separated')
    argparser.add_argument('--privacyStatus', choices=VALID_PRIVACY_STATUSES, default=VALID_PRIVACY_STATUSES[0],
                           help='Video privacy status.')
    args = argparser.parse_args()

    if not os.path.exists(args.file):
        argparser.error('Please specify a valid file using the --file= parameter.')

    return args


class VodMetadata(NamedTuple):
    title: str
    description: str


def find_vod_metadata(recordings_dir: str, credentials: OAuth2Credentials) -> Dict[str, VodMetadata]:
    TWITCH_USER_ID = '603039092'
    params = {
        'user_id': TWITCH_USER_ID,
        'period': 'week',
        'type': 'archive',
    }
    headers = {
        'Client-Id': credentials.client_id,
    }
    credentials.apply(headers)
    request = requests.Request('GET', f'https://api.twitch.tv/helix/videos', params=params, headers=headers)
    request = request.prepare()
    session = requests.Session()
    result = session.send(request)
    result.raise_for_status()
    log.debug('Twitch result:')
    log.debug(result.text)

    videos = result.json()['data']
    FILENAME_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}.mp4$')
    DURATION_REGEX = re.compile(r'^((\d+)h)?((\d+)m)?((\d+)s)?$')
    result: Dict[str, VodMetadata] = {}
    for f in os.listdir(recordings_dir):
        log.debug(f'Checking filename: {f}')
        if FILENAME_REGEX.match(f):
            log.info(f'Processing {f}...')
            for video in videos:
                # There are some cases where the Twitch "created_at" timestamp comes *after* the local file creation timestamp,
                # even if the local recording is started shortly after going live. Add a bit of a buffer to account for this.
                GRACE_PERIOD = datetime.timedelta(seconds=30)
                start_ts = dateutil.parser.isoparse(video['created_at'])
                start_ts = start_ts - GRACE_PERIOD
                match = DURATION_REGEX.match(video['duration'])
                assert match
                duration = datetime.timedelta(hours=int(match[2] or 0), minutes=int(match[4] or 0), seconds=int(match[6] or 0))
                end_ts = start_ts + duration

                vod_creation_ts = datetime.datetime.strptime(f, '%Y-%m-%d_%H-%M-%S.mp4')
                if platform.system() == 'Windows':
                    vod_creation_ts = vod_creation_ts.replace(tzinfo=dateutil.tz.tzwinlocal())
                else:
                    vod_creation_ts = vod_creation_ts.replace(tzinfo=dateutil.tz.tzlocal())

                # Make sure we don't try to upload in-progress VODs
                OLDNESS_THRESHOLD = datetime.timedelta(minutes=5)
                if end_ts <= datetime.datetime.now(datetime.timezone.utc) - OLDNESS_THRESHOLD:
                    if start_ts <= vod_creation_ts <= end_ts:
                        log.info(f'Found matching video for {f}: {video}')
                        result[os.path.join(recordings_dir, f)] = VodMetadata(video['title'], video['description'])
                        break
                else:
                    log.info(f'Skipping in-progress VOD: {f}')

    return result


def main():
    args = parse_args()

    # YOUTUBE_UPLOAD_SCOPE = 'https://www.googleapis.com/auth/youtube.upload'
    # youtube_credentials = get_oauth_credentials('youtube', 'client_secrets_youtube.json', YOUTUBE_UPLOAD_SCOPE, args)
    twitch_credentials = get_oauth_credentials('twitch', 'client_secrets_twitch.json', '', args)

    metadata = find_vod_metadata(RECORDINGS_DIR, twitch_credentials)
    log.info('metadata: %s', metadata)  # TODO

    # try:
    #     youtube = get_authenticated_service('youtube', 'v3', youtube_credentials)
    #     initialize_upload(youtube, args)
    # except HttpError as e:
    #     log.error(f'An HTTP error {e.resp.status} occurred:\n{e.content}')

    # TODO: move file to archive

    # TODO: clean old files from archive


if __name__ == '__main__':
    main()
