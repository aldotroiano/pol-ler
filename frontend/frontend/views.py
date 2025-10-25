import urllib.parse
import json
import re
import requests

from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.clickjacking import xframe_options_exempt
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.urls import reverse

from .forms import IndexForm
from .settings import DOWNLOADER_PAGE_URL, FEED_PAGE_URL

from .setup_tool import get_selection_tag_ids, build_xpathes_for_items
from .setup_tool_ext import build_xpath_results
from .models import Feed, Field, FeedField

def health(request):
    """Simple health check endpoint"""
    return HttpResponse('OK', status=200)

def index(request):
    if request.method == 'GET' and 'url' in request.GET:
        form = IndexForm(request.GET)
        if form.is_valid():
            val = URLValidator()
            try:
                url = request.GET['url']
                if not url.startswith('http'):
                    url = 'http://' + url
                val(url)
            except ValidationError as e:
                form.add_error('url', 'Invalid url')
            else:
                return HttpResponseRedirect('%s?url=%s' % (reverse('setup'), urllib.parse.quote(url)))
    else:
        form = IndexForm()

    return render(request, 'frontend/index.html', {'form': form})


@ensure_csrf_cookie
def setup(request):
    if request.method == 'GET' and 'url' in request.GET:
        external_page_url = DOWNLOADER_PAGE_URL + urllib.parse.quote(request.GET['url'], safe='')
        return render(request, 'frontend/setup.html',
                        {
                            'external_page_url': external_page_url,
                            'page_url': request.GET['url']
                        })

    return HttpResponseBadRequest('Url is required')

def _validate_html(html):

    def walk(tag):
        if (len(tag) != 3 or not isinstance(tag[0], str) or
                type(tag[1]) is not dict or 'tag-id' not in tag[1] or
                type(tag[2]) is not list):
            return False
        for t in tag[2]:
            if not walk(t):
                return False
        return True

    return walk(html)


def setup_get_selected_ids(request):
    if request.method == 'POST':
        obj = json.loads(request.body)
        if 'html' not in obj or 'names' not in obj:
            return HttpResponseBadRequest('"html" and "names" parameters are required')
        html_json = obj['html']
        item_names = obj['names']

        if not _validate_html(html_json):
            return HttpResponseBadRequest('html is invalid')

        xpathes = build_xpathes_for_items(item_names, html_json)
        if 'title' in xpathes[1]:
            xpathes[1]['link'] = _get_link_xpath(xpathes[1]['title'])

        resp = {
            'xpathes': xpathes,
            'ids': get_selection_tag_ids(item_names, html_json)
        }

        return HttpResponse(json.dumps(resp))

def _get_link_xpath(title_xpath):
    if title_xpath == './child::node()':
        return './ancestor-or-self::node()/@href'
    else:
        xpath = title_xpath[:len(title_xpath)-len('/child::node()')]
        return xpath +'/ancestor-or-self::node()/@href'

_BASIC_TITLE_ID=1
_BASIC_DESCRIPTION_ID=2
_BASIC_LINK_ID=3
_BASIC_DATE_ID=4

def _create_feed(url, xpathes, edited=False, name=None):
    feed_xpath = xpathes[0]
    item_xpathes = xpathes[1]

    feed = Feed(uri=url, xpath=feed_xpath, edited=edited, name=name)
    feed.save()

    fields = Field.objects.all()

    for field in fields:
        if field.id == _BASIC_LINK_ID and _BASIC_TITLE_ID in item_xpathes and not edited:
            ff = FeedField(feed=feed, field=field, xpath= _get_link_xpath(item_xpathes[_BASIC_TITLE_ID][0]))
            ff.save()
        elif field.id in item_xpathes:
            ff = FeedField(feed=feed, field=field, xpath=item_xpathes[field.id][0])
            ff.save()

    return feed.id

def setup_create_feed(request):
    if request.method == 'POST':
        obj = json.loads(request.body)
        if 'html' not in obj or 'names' not in obj or 'url' not in obj:
            return HttpResponseBadRequest('"html", "names" and "url" parameters are required')
        html_json = obj['html']
        item_names = obj['names']
        url = obj['url']
        name = obj.get('name', None)

        if not _validate_html(html_json):
            return HttpResponseBadRequest('html is invalid')

        xpathes = build_xpathes_for_items(item_names, html_json)

        field_xpathes = {}
        required = True
        if 'title' in xpathes[1]:
            field_xpathes[_BASIC_TITLE_ID] = [xpathes[1]['title'], required]
        if 'description' in xpathes[1]:
            field_xpathes[_BASIC_DESCRIPTION_ID] = [xpathes[1]['description'], required]
        if 'date' in xpathes[1]:
            field_xpathes[_BASIC_DATE_ID] = [xpathes[1]['date'], False]  # date is optional
        xpathes[1] = field_xpathes

        feed_id = _create_feed(url, xpathes, name=name)

        return HttpResponse(reverse('feeds'))

def _validate_selectors(selectors):
    if not isinstance(selectors, list) or len(selectors) != 2:
        return False
    feed_xpath = selectors[0]
    item_xpathes = selectors[1]

    if not isinstance(feed_xpath, str):
        return False
    if not isinstance(item_xpathes, dict):
        return False

    item_xpathes = {int(field_id): xpath for field_id, xpath in item_xpathes.items()}

    fields = Field.objects.all()

    item_xpathes_out = {}

    for field in fields:
        if field.id in item_xpathes:
            if not isinstance(item_xpathes[field.id], str):
                return False
            else:
                item_xpathes_out[field.id] = [item_xpathes[field.id], field.required]
    return [feed_xpath, item_xpathes_out]

def setup_validate_selectors(request):
    if request.method == 'POST':
        obj = json.loads(request.body)
        if 'selectors' not in obj or 'snapshot_time' not in obj:
            return HttpResponseBadRequest('"selectors" and "snapshot_time" are required')

        selectors = obj['selectors']
        file_name = obj['snapshot_time']

        if not re.match('^\d{10}\.\d+_[\da-f]{32}', file_name):
            return HttpResponseBadRequest('"snapshot_time" is invalid')

        validated_selectors = _validate_selectors(selectors)

        if not validated_selectors:
            return HttpResponseBadRequest('selectors are invalid')

        messages, posts, success = build_xpath_results(validated_selectors, file_name)

        return HttpResponse(json.dumps({'success': success, 'messages': messages, 'posts': posts}))

def setup_create_feed_ext(request):
    if request.method == 'POST':
        obj = json.loads(request.body)
        if 'selectors' not in obj or 'snapshot_time' not in obj or 'url' not in obj:
            return HttpResponseBadRequest('"selectors", "snapshot_time" and "url" are required')

        selectors = obj['selectors']
        file_name = obj['snapshot_time']
        name = obj.get('name', None)

        if not re.match('^\d{10}\.\d+_[\da-f]{32}', file_name):
            return HttpResponseBadRequest('"snapshot_time" is invalid')

        validated_selectors = _validate_selectors(selectors)

        if not validated_selectors:
            return HttpResponseBadRequest('selectors are invalid')

        messages, posts, success = build_xpath_results(validated_selectors, file_name)

        if success:
            url = obj['url']
            feed_id = _create_feed(url, validated_selectors, True, name=name)
            return HttpResponse(json.dumps({'success': True, 'url': reverse('feeds')}))
        else:
            return HttpResponse(json.dumps({'success': False, 'messages': messages}))


def feeds(request):
    if request.method == 'GET':
        feeds = Feed.objects.all().order_by('-created')
        return render(request, 'frontend/feeds.html', {'feeds': feeds})
    
    return HttpResponseBadRequest('Only GET method supported')

def delete_feed(request, feed_id):
    if request.method == 'POST':
        try:
            feed = Feed.objects.get(id=feed_id)
            feed.delete()
            return HttpResponseRedirect(reverse('feeds'))
        except Feed.DoesNotExist:
            return HttpResponseBadRequest('Feed not found')
    
    return HttpResponseBadRequest('Only POST method supported')

def edit_feed_name(request, feed_id):
    if request.method == 'POST':
        try:
            feed = Feed.objects.get(id=feed_id)
            new_name = request.POST.get('name', '').strip()
            feed.name = new_name if new_name else None
            feed.save()
            return HttpResponseRedirect(reverse('feeds'))
        except Feed.DoesNotExist:
            return HttpResponseBadRequest('Feed not found')
    
    return HttpResponseBadRequest('Only POST method supported')

def edit_feed_names(request):
    if request.method == 'POST':
        # Get all feed names from the form
        feed_names = {}
        for key, value in request.POST.items():
            if key.startswith('feed_name_'):
                feed_id = key.replace('feed_name_', '')
                try:
                    feed_id = int(feed_id)
                    feed_names[feed_id] = value.strip() if value.strip() else None
                except ValueError:
                    continue
        
        # Update all feeds
        updated_count = 0
        for feed_id, new_name in feed_names.items():
            try:
                feed = Feed.objects.get(id=feed_id)
                feed.name = new_name
                feed.save()
                updated_count += 1
            except Feed.DoesNotExist:
                continue
        
        return HttpResponseRedirect(reverse('feeds'))
    
    return HttpResponseBadRequest('Only POST method supported')

@xframe_options_exempt
def downloader_proxy(request):
    """Modern downloader that works without Twisted server"""
    if request.method == 'GET':
        url_param = request.GET.get('url', '')
        if not url_param:
            return HttpResponseBadRequest('URL parameter is required')
        
        # Validate URL
        if not url_param.startswith(('http://', 'https://')):
            url_param = 'http://' + url_param
        
        try:
            # Use the existing Twisted server if available, otherwise fallback
            downloader_url = f"http://localhost:1234/?url={url_param}"
            response = requests.get(downloader_url, timeout=60)
            return HttpResponse(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type', 'text/html')
            )
        except requests.exceptions.Timeout:
            return HttpResponseBadRequest("Downloader service timeout - the page took too long to download")
        except requests.exceptions.ConnectionError:
            # Fallback: return a simple message if Twisted server is not running
            return HttpResponse(f"""
            <html><body>
            <h1>RSS Feed Downloader</h1>
            <p>URL: {url_param}</p>
            <p>Note: Downloader service is not running. Please start the Twisted server.</p>
            <p>To start: <code>python downloader.py</code></p>
            </body></html>
            """, content_type='text/html')
        except requests.exceptions.RequestException as e:
            return HttpResponseBadRequest(f"Downloader service error: {str(e)}")
    
    return HttpResponseBadRequest('Only GET method supported')

def feed_proxy(request, feed_id):
    """Modern feed proxy that works without Twisted server"""
    if request.method == 'GET':
        # Include query parameters (like ?sanitize=Y)
        query_string = request.GET.urlencode()
        feed_url = f"http://localhost:1234/feed/{feed_id}"
        if query_string:
            feed_url += f"?{query_string}"
        
        try:
            response = requests.get(feed_url, timeout=60)
            return HttpResponse(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type', 'application/xml')
            )
        except requests.exceptions.Timeout:
            return HttpResponseBadRequest("Feed service timeout")
        except requests.exceptions.ConnectionError:
            # Fallback: return a simple RSS feed if Twisted server is not running
            return HttpResponse(f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>pol-ler Feed {feed_id}</title>
        <link>http://localhost:8088/feed/{feed_id}</link>
        <description>Feed service is not running. Please start the Twisted server.</description>
        <item>
            <title>Service Not Available</title>
            <link>http://localhost:8088/feed/{feed_id}</link>
            <description>To start the feed service, run: python downloader.py</description>
        </item>
    </channel>
</rss>""", content_type='application/xml')
        except requests.exceptions.RequestException as e:
            return HttpResponseBadRequest(f"Feed service error: {str(e)}")
    
    return HttpResponseBadRequest('Only GET method supported')