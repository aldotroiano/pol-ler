from datetime import datetime
from hashlib import md5
import json
import pickle
import time, sys, traceback
import re

from lxml import etree

from twisted.web import server, resource
from twisted.internet import reactor, endpoints, defer
from twisted.web.client import Agent, BrowserLikeRedirectAgent, PartialDownloadError, HTTPConnectionPool
from twisted.web.server import NOT_DONE_YET
from twisted.web.http_headers import Headers
from twisted.web.http import INTERNAL_SERVER_ERROR
from twisted.web.html import escape
twisted_headers = Headers
from twisted.logger import Logger

from scrapy.http.response.text import TextResponse
from scrapy.downloadermiddlewares.httpcompression import HttpCompressionMiddleware
from scrapy.http.request import Request
from scrapy.http import Headers
from scrapy.responsetypes import responsetypes
from scrapy.core.downloader.contextfactory import ScrapyClientContextFactory
from scrapy.selector import Selector

from pol.log import LogHandler
from .feed import Feed
from .client import ppReadBody, IGNORE_SIZE
from .js_downloader import get_js_downloader, cleanup_js_downloader

from twisted.logger import Logger


log = Logger()

class Downloader(object):

    # Domains that typically require JavaScript rendering
    JS_DOMAINS = {
        'medium.com', 'netflixtechblog.com', 'dev.to', 'hashnode.com',
        'substack.com', 'ghost.io', 'notion.so', 'airtable.com'
    }

    def __init__(self, feed, debug, snapshot_dir, stat_tool, memon, request,
                 url, feed_config, selector_defer, sanitize, max_size):
        self.feed = feed
        self.debug = debug
        self.snapshot_dir = snapshot_dir
        self.stat_tool = stat_tool
        self.memon = memon
        self.request = request
        self.url = url
        self.feed_config=feed_config
        self.selector_defer = selector_defer
        self.sanitize = sanitize
        self.max_size = max_size

    def _needs_js_rendering(self, url):
        """Check if a URL needs JavaScript rendering."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix for comparison
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain in self.JS_DOMAINS
        except:
            return False

    def _download_with_js(self, url, user_agent):
        """Download a page using JavaScript rendering."""
        try:
            js_downloader = get_js_downloader(user_agent, headless=True, timeout=30)
            html_content, success, error = js_downloader.download_page(url)
            
            if success and html_content:
                # Create a mock response object similar to what Twisted would return
                from scrapy.http import TextResponse
                from scrapy.http import Headers
                
                response = TextResponse(
                    url=url,
                    status=200,
                    headers=Headers({'Content-Type': 'text/html; charset=utf-8'}),
                    body=html_content.encode('utf-8')
                )
                return response, None
            else:
                return None, error or "Failed to download with JavaScript"
                
        except Exception as e:
            return None, f"JavaScript downloader error: {str(e)}"

    def html2json(self, el):
        return [
            el.tag,
            {k: v for (k,v) in el.items() if k in ['tag-id', 'class']},  # attributes
            [self.html2json(e) for e in el.getchildren() if isinstance(e, etree.ElementBase)]
        ]

    def _saveResponse(self, headers, url, tree):
        # save html for extended selectors
        file_name = '%s_%s' % (time.time(), md5(url.encode('utf-8')).hexdigest())
        file_path = self.snapshot_dir + '/' + file_name
        with open(file_path, 'w') as f:
            f.write(url + '\n')
            for k, v in headers.items():
                for vv in v:
                    f.write('%s: %s\n' % (k, vv))
            f.write('\n\n' + etree.tostring(tree, encoding='utf-8', method='html').decode('utf-8'))
        return file_name

    def sanitizeAndNumerate(self, selector, numerate=True, sanitize_anchors=True):

        tree = selector.root.getroottree()

        i = 1
        for bad in tree.xpath("//*"):
            # remove scripts and iframes
            if bad.tag in ['script', 'iframe']:
                bad.getparent().remove(bad)
                continue
            
            if numerate:
                # set tag-id attribute
                bad.attrib['tag-id'] = str(i)
                i += 1

            # sanitize anchors
            if sanitize_anchors and bad.tag == 'a' and 'href' in bad.attrib:
                bad.attrib['origin-href'] = bad.attrib['href']
                del bad.attrib['href']

            # remove html events
            for attr in list(bad.attrib.keys()):
                if attr.startswith('on'):
                    del bad.attrib[attr]

            # make clickable for mobile (but not for link/style tags)
            if bad.tag not in ['link', 'style', 'meta']:
                bad.attrib['onclick'] = ""

            # sanitize forms
            if bad.tag == 'form':
                bad.attrib['onsubmit'] = "return false"


    def setBaseAndRemoveScriptsAndMore(self, selector, headers, url):
        selector.remove_namespaces()

        tree = selector.root.getroottree()

        if self.snapshot_dir:
            file_name = self._saveResponse(headers, url, tree)
        else:
            file_name = 'DISABLED'

        # set base url to html document
        head = tree.xpath("//head")
        if head:
            head = head[0]
            base = head.xpath("./base")
            if base:
                base = base[0]
            else:
                base = etree.Element("base")
                head.insert(0, base)
            base.set('href', url if isinstance(url, str) else url.decode('utf-8'))

        self.sanitizeAndNumerate(selector)

        body = tree.xpath("//body")
        if body:
            # append html2json js object
            jsobj = self.html2json(tree.getroot())
            script = etree.Element('script', {'type': 'text/javascript'})
            script.text = '\n'.join((
                            'var html2json = ' + json.dumps(jsobj) + ';',
                            'var snapshot_time = "' + file_name + '";'
                        ))
            body[0].append(script)

        return etree.tostring(tree, method='html').decode('utf-8')

    def buildScrapyResponse(self, response, body, url):
        status = response.code
        # getAllRawHeaders() returns bytes, need to decode them
        headers = Headers({
            k.decode('utf-8') if isinstance(k, bytes) else k: 
            ','.join([h.decode('utf-8') if isinstance(h, bytes) else h for h in v]) 
            for k, v in response.headers.getAllRawHeaders()
        })
        # Ensure url is a string, not bytes
        if isinstance(url, bytes):
            url = url.decode('utf-8')
        respcls = responsetypes.from_args(headers=headers, url=url)
        return respcls(url=url, status=status, headers=headers, body=body)

    def error_html(self, msg):
        return "<html><body>%s</body></html>" % msg.replace("\n", "<br/>\n")

    def downloadError(self, error):
        # read for details: https://stackoverflow.com/questions/29423986/twisted-giving-twisted-web-client-partialdownloaderror-200-ok
        if error.type is PartialDownloadError and error.value.status == '200':
            d = defer.Deferred()
            reactor.callLater(0, d.callback, error.value.response) # error.value.response is response_str
            d.addCallback(self.downloadDone)
            d.addErrback(self.downloadError)
            return

        if self.selector_defer:
            self.selector_defer.errback(error)
        else:
            try:
                if self.stat_tool:
                    feed_id = self.feed_config and self.feed_config['id']
                    s_url = None
                    if not feed_id:
                        feed_id = 0
                        s_url = self.url
                    self.stat_tool.trace(
                            ip = self.request.getHeader('x-real-ip') or self.request.client.host,
                            feed_id = feed_id,
                            post_cnt=0,
                            new_post_cnt=0,
                            url=s_url,
                            ex_msg=error.getErrorMessage(),
                            ex_callstack=error.getTraceback()
                        )
                else:
                    error_msg = error.getErrorMessage()
                    if isinstance(error_msg, bytes):
                        error_msg = error_msg.decode('utf-8', errors='replace')
                    traceback_msg = error.getTraceback()
                    if isinstance(traceback_msg, bytes):
                        traceback_msg = traceback_msg.decode('utf-8', errors='replace')
                    request_uri = self.request.uri
                    if isinstance(request_uri, bytes):
                        request_uri = request_uri.decode('utf-8', errors='replace')
                    url = self.url
                    if isinstance(url, bytes):
                        url = url.decode('utf-8', errors='replace')
                    sys.stderr.write('\n'.join([
                        str(datetime.utcnow()), 
                        str(request_uri), 
                        str(url), 
                        'Downloader error: ' + str(error_msg),
                        'Traceback: ' + str(traceback_msg)
                    ]) + '\n')
            except:
                traceback.print_exc(file=sys.stdout)

            self.request.setResponseCode(INTERNAL_SERVER_ERROR)
            if self.debug:
                error_msg = error.getErrorMessage()
                if isinstance(error_msg, bytes):
                    error_msg = error_msg.decode('utf-8', errors='replace')
                traceback_msg = error.getTraceback()
                if isinstance(traceback_msg, bytes):
                    traceback_msg = traceback_msg.decode('utf-8', errors='replace')
                self.request.write(('Downloader error: ' + error_msg).encode('utf-8'))
                self.request.write(('Traceback: ' + traceback_msg).encode('utf-8'))
            else:
                error_msg = error.getErrorMessage()
                if isinstance(error_msg, bytes):
                    error_msg = error_msg.decode('utf-8', errors='replace')
                err_message = self.error_html('<h1>Pol-ler says: "Something wrong"</h1> <p><b>Try refreshing the page</p> <p><i>Scary mantra: %s</i></p>' % escape(error_msg))
                self.request.write(err_message.encode('utf-8'))

            self.request.finish()

    def downloadStarted(self, response):
        self.response = response

        d = ppReadBody(response, self.max_size)
        d.addCallback(self.downloadDone)
        d.addErrback(self.downloadError)
        return response

    def downloadDone(self, response_str):
        url = self.response.request.absoluteURI

        print('Response <%s> ready (%s bytes)' % (url, len(response_str)))
        sresponse = self.buildScrapyResponse(self.response, response_str, url)

        if self.selector_defer:
            self.selector_defer.callback(sresponse)
        else:
            self.writeResponse(sresponse)
            self.run_memon()

    def writeResponse(self, sresponse):
        sresponse = HttpCompressionMiddleware().process_response(Request(sresponse.url), sresponse, None)

        response_headers = self.prepare_response_headers(sresponse.headers)

        if (isinstance(sresponse, TextResponse)):
            ip = self.request.getHeader('x-real-ip') or self.request.client.host
            # Use .text property instead of deprecated body_as_unicode()
            body_text = sresponse.text if hasattr(sresponse, 'text') else sresponse.body_as_unicode()
            response_str = self.prepare_response_str(sresponse.selector, sresponse.headers, body_text, sresponse.url, ip)
            if self.feed_config:
                response_headers = {b"Content-Type": b'text/xml; charset=utf-8'}
        else: # images and such
            response_str = sresponse.body

        for k, v in response_headers.items():
            self.request.setHeader(k, v)

        # Ensure response_str is bytes for Python 3
        if isinstance(response_str, str):
            response_str = response_str.encode('utf-8')
        self.request.write(response_str)
        self.request.finish()

    def prepare_response_headers(self, headers):
        return {}

    def prepare_response_str(self, selector, headers, page_unicode, url, ip=None):
        if self.feed_config:
            if self.sanitize:
                self.sanitizeAndNumerate(selector, numerate=False, sanitize_anchors=False)
            [response_str, post_cnt, new_post_cnt] = self.feed.buildFeed(selector, page_unicode, self.feed_config)
            if self.stat_tool:
                self.stat_tool.trace(ip=ip, feed_id=self.feed_config['id'], post_cnt=post_cnt, new_post_cnt=new_post_cnt)
        else:
            response_str = self.setBaseAndRemoveScriptsAndMore(selector, headers, url)
            if self.stat_tool:
                self.stat_tool.trace(ip=ip, feed_id=0, post_cnt=0, new_post_cnt=0, url=url)
        return response_str


    def run_memon(self):
        if self.memon:
            d = defer.Deferred()
            reactor.callLater(0, d.callback, None)
            d.addCallback(self.memon.show_diff)
            d.addErrback(lambda err: print("Memory Monitor error: %s\nPGC traceback: %s" % (err.getErrorMessage(), err.getTraceback())))


class Site(resource.Resource):
    isLeaf = True

    feed_regexp = re.compile(b'^/feed/(\d{1,10})')


    def __init__(self, db_creds, snapshot_dir, user_agent, debug=False, limiter=None, memon=None, stat_tool=None, prefetch_dir=None, feed=None, downloadercls=None, max_size=IGNORE_SIZE):
        self.db_creds = db_creds
        self.snapshot_dir = snapshot_dir
        self.user_agent = user_agent
        self.limiter = limiter
        self.prefetch_dir = prefetch_dir

        self.feed = feed or Feed(db_creds)
        self.debug = debug
        self.stat_tool = stat_tool
        self.memon= memon
        self.max_size = max_size
        self.downloadercls = downloadercls or Downloader

    def startRequest(self, request, url, feed_config = None, selector_defer=None, sanitize=False, js_mode='auto'):
        downloader = self.downloadercls(self.feed, self.debug, self.snapshot_dir, self.stat_tool, self.memon,
                                        request=request, url=url, feed_config=feed_config,
                                        selector_defer=selector_defer, sanitize=sanitize, max_size=self.max_size)

        sresponse = self.tryLocalPage(url)
        if sresponse:
            if selector_defer:
                reactor.callLater(0, selector_defer.callback, sresponse)
            else:
                downloader.writeResponse(request, sresponse, feed_config)
        else:
            # Check if this URL needs JavaScript rendering
            use_js = False
            if js_mode == 'on':
                use_js = True
            elif js_mode == 'off':
                use_js = False
            else: # auto
                use_js = downloader._needs_js_rendering(url)

            if use_js:
                print(f'Using JavaScript rendering for: {url}')
                js_response, js_error = downloader._download_with_js(url, self.user_agent)
                if js_response:
                    if selector_defer:
                        reactor.callLater(0, selector_defer.callback, js_response)
                    else:
                        downloader.writeResponse(request, js_response, feed_config)
                    return
                else:
                    print(f'JavaScript rendering failed for {url}: {js_error}')
                    # Fall back to regular download
            agent = BrowserLikeRedirectAgent(
                Agent(reactor,
                    contextFactory=ScrapyClientContextFactory(), # skip certificate verification
                    connectTimeout=10),
                    #pool=pool),
                redirectLimit=5
            )

            d = agent.request(
                b'GET',
                url,
                twisted_headers({
                    'Accept': ['text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'],
                    'Accept-Encoding': ['gzip, deflate, br'],
                    'Accept-Language': ['en-US,en;q=0.9'],
                    'Cache-Control': ['no-cache'],
                    'Pragma': ['no-cache'],
                    'Sec-Ch-Ua': ['"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'],
                    'Sec-Ch-Ua-Mobile': ['?0'],
                    'Sec-Ch-Ua-Platform': ['"macOS"'],
                    'Sec-Fetch-Dest': ['document'],
                    'Sec-Fetch-Mode': ['navigate'],
                    'Sec-Fetch-Site': ['none'],
                    'Sec-Fetch-User': ['?1'],
                    'Upgrade-Insecure-Requests': ['1'],
                    'User-Agent': [self.user_agent]
                }),
                None
            )
            print('Request <GET %s> started' % (url,))
            d.addCallback(downloader.downloadStarted)
            d.addErrback(downloader.downloadError)

    def tryLocalPage(self, url):
        if self.prefetch_dir:
            from urllib.parse import urlparse
            m = md5(url.encode('utf-8')).hexdigest()
            domain = urlparse(url).netloc
            try:
                with open(self.prefetch_dir + '/' + m + '.' + domain, 'rb') as f:
                    return pickle.load(f)
            except IOError:
                pass
        return None

    def render_GET(self, request):
        '''
        Render page for frontend or RSS feed
        '''
        if b'url' in request.args: # page for frontend
            url = request.args[b'url'][0]
            js_mode = b'auto'
            if b'js' in request.args:
                val = request.args[b'js'][0]
                if val in [b'on', b'off', b'auto']:
                    js_mode = val

            self.startRequest(request, url, sanitize=True, js_mode=js_mode.decode('utf-8') if isinstance(js_mode, bytes) else js_mode)
            return NOT_DONE_YET
        elif self.feed_regexp.match(request.uri) is not None: # feed

            feed_id = self.feed_regexp.match(request.uri).groups()[0]
            # Decode bytes to string and convert to int for Python 3
            if isinstance(feed_id, bytes):
                feed_id = feed_id.decode('utf-8')
            feed_id = int(feed_id)
            sanitize = request.uri.endswith(b'?sanitize=Y')

            time_left = self.limiter.check_request_time_limit(request.uri) if self.limiter else 0
            if time_left:
                request.setResponseCode(429)
                request.setHeader('Retry-After', str(time_left) + ' seconds')
                return b'Too Many Requests. Retry after %s seconds' % (str(time_left))
            else:
                res = self.feed.getFeedData(feed_id)

                if isinstance(res, str): # error message
                    return res.encode('utf-8')

                url, feed_config = res
                self.startRequest(request, url if isinstance(url, bytes) else url.encode('utf-8'), feed_config, sanitize=sanitize)
                return NOT_DONE_YET
        else: # neither page and feed
            return b'Url is invalid'


class Server(object):

    def __init__(self, port, db_creds, snapshot_dir, user_agent, debug=False, limiter=None, memon=None, stat_tool=None, prefetch_dir=None, feed=None, sitecls=None, downloadercls=None, max_size=IGNORE_SIZE):
        self.port = port
        self.db_creds = db_creds
        self.snapshot_dir = snapshot_dir
        self.user_agent = user_agent
        self.debug = debug
        self.limiter = limiter
        self.memon = memon
        self.stat_tool=stat_tool
        self.prefetch_dir = prefetch_dir

        self.log_handler = LogHandler()

        if not sitecls:
            sitecls = Site

        self.site = sitecls(self.db_creds, self.snapshot_dir, self.user_agent, self.debug, self.limiter, self.memon, self.stat_tool, self.prefetch_dir, feed, downloadercls=downloadercls, max_size=max_size)

    def requestSelector(self, url=None, feed_config=None):
        d = defer.Deferred()
        self.site.startRequest(None, url, feed_config=feed_config, selector_defer=d)
        return d

    def run(self):
        endpoints.serverFromString(reactor, "tcp:%s" % self.port).listen(server.Site(self.site))
        reactor.run()
