#!/usr/bin/env python3

import argparse
import datetime
import dateutil.parser
from email.message import EmailMessage
import http.client
import httplib2
import logging
import os
import pathlib
import platform
import random
import re
import requests
import shutil
import smtplib
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
from types import TracebackType
from typing import Collection, Dict, List, NamedTuple, Optional, Type

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
log.setLevel(logging.DEBUG)

stdout_handler = logging.StreamHandler(sys.stdout)
log.addHandler(stdout_handler)

file_handler = logging.FileHandler(os.path.join(RECORDINGS_DIR, 'logs', LOG_FILE_NAME))
file_handler.setLevel(logging.DEBUG)
log.addHandler(file_handler)


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

    if exc_type != KeyboardInterrupt:
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


class UploadError(Exception):
    pass


class PlaylistError(Exception):
    pass


class VodMetadata(NamedTuple):
    title: str
    description: str
    start_ts: datetime.datetime
    end_ts: datetime.datetime


def parse_args() -> argparse.Namespace:
    VALID_PRIVACY_STATUSES = ('public', 'private', 'unlisted')

    argparser.add_argument('--upload', action='store_true', help='Do YouTube upload step')
    argparser.add_argument('--add-to-playlist', action='store_true', help='Add the uploaded video to a matching playlist')
    argparser.add_argument('--move-finished-to-archive', action='store_true', help='Move finished uploads to archive directory')
    argparser.add_argument('--concat-consecutive-videos', action='store_true', help='Combine successive clips before uploading')
    argparser.add_argument('--clean-archive', action='store_true', help='Clean old videos from archive directory')
    argparser.add_argument('--privacy-status', choices=VALID_PRIVACY_STATUSES, default='private', help='Video privacy status')
    argparser.add_argument('--schedule', action='store_true',
                           help='Schedule for future time instead of publishing immediately. Implies --privacy-status=private')
    args = argparser.parse_args()

    if args.schedule:
        args.privacy_status = 'private'  # Required when using status.publishAt

    return args


def main() -> None:
    args = parse_args()

    stdout_handler.setLevel(args.logging_level)

    # Set up OAuth
    log.info('Establishing API credentials')
    YOUTUBE_SCOPE = 'https://www.googleapis.com/auth/youtube'
    YOUTUBE_UPLOAD_SCOPE = 'https://www.googleapis.com/auth/youtube.upload'
    youtube_credentials = get_oauth_credentials('youtube', 'client_secrets_youtube.json', [YOUTUBE_SCOPE, YOUTUBE_UPLOAD_SCOPE], args)
    twitch_credentials = get_oauth_credentials('twitch', 'client_secrets_twitch.json', [''], args)
    # The YouTube API client handles refreshing tokens automatically, but for Twitch I have to handle it myself
    log.info('Refreshing Twitch token')
    twitch_credentials.refresh(httplib2.Http())

    # Find titles and descriptions for videos that are staged for uploading
    metadata = find_vod_metadata(RECORDINGS_DIR, twitch_credentials)

    if args.concat_consecutive_videos:
        to_concat = find_consecutive_videos(metadata)
        for filenames in to_concat:
            output_filename = concat_consecutive_videos(filenames)
            metadata = update_metadata_for_concat(metadata, filenames, output_filename)

            # Move original uncombined videos to archive
            for old_filename in filenames:
                if args.move_finished_to_archive:
                    log.info(f'Moving {old_filename} to {ARCHIVE_DIR}')
                    shutil.move(old_filename, ARCHIVE_DIR)
                else:
                    log.info(f'Would have moved {old_filename} to {ARCHIVE_DIR}')

    if args.upload:
        # Do the upload
        youtube = get_authenticated_service('youtube', 'v3', youtube_credentials)
        for filename, (title, description, start_ts, end_ts) in metadata.items():
            publish_at = None
            if args.schedule:
                publish_at = end_ts + datetime.timedelta(days=1)  # 24 hours after stream end per Twitch affiliate/parter TOS
                log.info(f'Uploading "{title}" ({filename}) to be published at {publish_at}')
            else:
                log.info(f'Uploading "{title}" ({filename})')
            video_id = upload_video_to_youtube(
                youtube,
                filename,
                title=title,
                description=description,
                category='28',  # "Science & Technology"
                privacy=args.privacy_status,
                publish_at=publish_at,
                tags=['game engine', 'game development', 'indie', 'programming', 'coding', 'stream'],
            )

            if args.add_to_playlist:
                add_video_to_matching_playlist(youtube, title, video_id)

            # Move uploaded file to archive
            if args.move_finished_to_archive:
                log.info(f'Moving {filename} to {ARCHIVE_DIR}')
                shutil.move(filename, ARCHIVE_DIR)
            else:
                log.info(f'Would have moved {filename} to {ARCHIVE_DIR}')

    # Clean old files from archive
    clean_archive(ARCHIVE_DIR, dry_run=not args.clean_archive)


def get_oauth_credentials(
        service_name: str,
        secrets_file: str,
        scopes: Collection[str],
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
        flow = flow_from_clientsecrets(secrets_file, scope=scopes, message=MISSING_CLIENT_SECRETS_MESSAGE)
        credentials = run_flow(flow, storage, auth_server_args)

    return credentials


def find_vod_metadata(recordings_dir: str, credentials: OAuth2Credentials) -> Dict[str, VodMetadata]:
    log.info('Looking up VOD metadata from Twitch')
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
    for f in sorted(os.listdir(recordings_dir)):
        log.debug(f'Checking filename: {f}')
        if FILENAME_REGEX.match(f):
            log.info(f'Trying to find Twitch metadata for "{f}"...')
            for video in videos:
                GRACE_PERIOD = datetime.timedelta(seconds=30)
                start_ts = dateutil.parser.isoparse(video['created_at'])
                match = DURATION_REGEX.match(video['duration'])
                assert match
                duration = datetime.timedelta(hours=int(match[2] or 0), minutes=int(match[4] or 0), seconds=int(match[6] or 0))
                end_ts = start_ts + duration

                vod_creation_ts = datetime.datetime.strptime(f, '%Y-%m-%d_%H-%M-%S.mp4')
                if platform.system() == 'Windows':
                    vod_creation_ts = vod_creation_ts.replace(tzinfo=dateutil.tz.tzwinlocal())
                else:
                    vod_creation_ts = vod_creation_ts.replace(tzinfo=dateutil.tz.tzlocal())

                # There are some cases where the Twitch "created_at" timestamp comes *after* the local file creation timestamp,
                # even if the local recording is started shortly after going live. Add a bit of a buffer to account for this.
                adjusted_start_ts = start_ts - GRACE_PERIOD
                # Make sure we don't try to upload in-progress VODs
                OLDNESS_THRESHOLD = datetime.timedelta(minutes=5)
                if adjusted_start_ts <= vod_creation_ts <= end_ts:
                    if end_ts <= datetime.datetime.now(datetime.timezone.utc) - OLDNESS_THRESHOLD:
                        log.info(f'Found matching video for {f}: {video}')
                        result[os.path.join(recordings_dir, f)] = VodMetadata(video['title'], video['description'], start_ts, end_ts)
                    else:
                        log.info(f'Skipping in-progress VOD: {f}')
                    break

    return result


def find_consecutive_videos(metadata: Dict[str, VodMetadata]) -> List[List[str]]:
    CLOSENESS_THRESHOLD = datetime.timedelta(minutes=30)
    last_end_ts = datetime.datetime.min
    if platform.system() == 'Windows':
        last_end_ts = last_end_ts.replace(tzinfo=dateutil.tz.tzwinlocal())
    else:
        last_end_ts = last_end_ts.replace(tzinfo=dateutil.tz.tzlocal())
    results: List[List[str]] = []
    current = None
    for filename, vod in sorted(metadata.items()):
        if last_end_ts + CLOSENESS_THRESHOLD >= vod.start_ts:
            # Videos are close enough
            current.append(filename)
        else:
            # Start of a new stream, reset
            if current is not None:
                results.append(current)
            current = [filename]
        last_end_ts = vod.end_ts
    if current is not None:
        results.append(current)
    results = [result for result in results if len(result) >= 2]

    return results


def concat_consecutive_videos(filenames: List[str]) -> str:
    assert len(filenames) >= 2
    input_file = pathlib.Path(filenames[0])
    output_name = str(input_file.with_stem(f'{input_file.stem}_combined'))
    list_file = tempfile.NamedTemporaryFile('w+', delete=False)
    try:
        log.info(f'Combining files: {filenames}')
        list_file.writelines(f"file '{f}'\n" for f in filenames)
        cmd = rf"""ffmpeg -f concat -safe 0 -n -i {list_file.name} -c copy {output_name}"""
        log.info(f'Running command: {cmd}')
        list_file.close()  # The Windows filesystem is dumb
        proc = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        log.info(f'Stdout: {proc.stdout}')
        log.warning(f'Stderr: {proc.stderr}')
    finally:
        os.remove(list_file.name)

    return output_name


def update_metadata_for_concat(old_metadata: Dict[str, VodMetadata], old_filenames: List[str], new_filename: str) -> Dict[str, VodMetadata]:
    assert len(old_filenames) >= 2
    first_video = old_metadata[old_filenames[0]]
    last_video = old_metadata[old_filenames[-1]]

    new_metadata = {filename: metadata for filename, metadata in old_metadata.items() if filename not in old_filenames}
    new_metadata[new_filename] = VodMetadata(
        title=first_video.title,
        description=first_video.description,
        start_ts=first_video.start_ts,
        end_ts=last_video.end_ts,
    )

    return new_metadata


def get_authenticated_service(
        service_name: str,
        api_version: str,
        credentials: OAuth2Credentials,
) -> Resource:
    return build(service_name, api_version, http=credentials.authorize(httplib2.Http()))


def upload_video_to_youtube(
        youtube: Resource,
        filename: str,
        title: str,
        description: str,
        category: str,
        privacy: str,
        publish_at: Optional[datetime.datetime] = None,
        tags: Optional[Collection[str]] = None,
) -> str:
    body = {
        'snippet': {
            'title': title,
            'description': description,
            'tags': tags,
            'categoryId': category,
        },
        'status': {
            'privacyStatus': privacy,
        },
    }
    if publish_at is not None:
        body['status']['publishAt'] = publish_at.isoformat()

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
        media_body=MediaFileUpload(filename, chunksize=-1, resumable=True),
    )

    return _resumable_upload(insert_request)


# This method implements an exponential backoff strategy to resume a failed upload.
def _resumable_upload(insert_request) -> str:
    # Maximum number of times to retry before giving up.
    MAX_RETRIES = 10

    # Always retry when these exceptions are raised.
    RETRIABLE_EXCEPTIONS = (httplib2.HttpLib2Error, IOError, http.client.NotConnected,
        http.client.IncompleteRead, http.client.ImproperConnectionState,
        http.client.CannotSendRequest, http.client.CannotSendHeader,
        http.client.ResponseNotReady, http.client.BadStatusLine)

    # Always retry when an apiclient.errors.HttpError with one of these status codes is raised.
    RETRIABLE_STATUS_CODES = {500, 502, 503, 504}

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
                    return response['id']
                else:
                    raise UploadError(f'The upload failed with an unexpected response: {response}')
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
                raise UploadError('No longer attempting to retry.')

            max_sleep = 2 ** retry
            sleep_seconds = random.random() * max_sleep
            log.info(f'Sleeping {sleep_seconds} seconds and then retrying...')
            time.sleep(sleep_seconds)


def add_video_to_matching_playlist(youtube: Resource, title: str, video_id: str) -> None:
    VALID_PLAYLISTS = {
        re.compile(r'^Game Engine '): 'PLDKWjXpoaOxtT0OyavgpNPiqH8PL-AjY4',
        re.compile(r'^Bonus Stream '): 'PLDKWjXpoaOxsF_5Lc_zsR0lJTh0viGSIK',
    }

    playlist_id = [p_id for regex, p_id in VALID_PLAYLISTS.items() if regex.match(title)]
    if len(playlist_id) != 1:
        raise PlaylistError(f'Could not determine playlist for video "{title}" ({video_id})')
    playlist_id = playlist_id[0]

    body = {
        'snippet': {
            'playlistId': playlist_id,
            'resourceId': {
                'kind': 'youtube#video',
                'videoId': video_id,
            },
        },
    }
    insert_request = youtube.playlistItems().insert(
        part=','.join(body.keys()),
        body=body,
    )
    response = insert_request.execute(num_retries=3)
    if response is not None and 'id' in response:
        log.info(f'Playlist item {response["id"]} was successfully added.')
    else:
        raise PlaylistError(f'Invalid response: {response}')


def listdir_absolute(d: str) -> List[str]:
    return [os.path.join(d, f) for f in os.listdir(d)]


def clean_archive(archive_dir: str, dry_run: bool = False) -> None:
    log.info('Considering archive cleanup')
    MIN_COUNT = 100
    MAX_SIZE_BYTES = 1_000_000_000_000
    archive_files = listdir_absolute(archive_dir)
    file_sizes = {f: os.path.getsize(f) for f in archive_files}
    while len(file_sizes) > MIN_COUNT and sum(file_sizes.values()) > MAX_SIZE_BYTES:
        oldest_file = sorted(file_sizes.keys())[0]  # Filenames are of the form YYYY-mm-dd_HH-MM-SS.mp4
        if not dry_run:
            log.info(f'Deleting {oldest_file}')
            os.remove(oldest_file)
        else:
            log.info(f'Would have deleted {oldest_file}')
        file_sizes.pop(oldest_file)


if __name__ == '__main__':
    main()
