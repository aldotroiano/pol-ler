"""
JavaScript-enabled downloader for handling JS-heavy websites like Medium, Netflix Tech Blog, etc.
"""

import time
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from twisted.logger import Logger

log = Logger()

class JSEnabledDownloader:
    """
    Downloader that uses Selenium WebDriver to render JavaScript-heavy websites.
    """
    
    def __init__(self, user_agent, headless=True, timeout=30):
        self.user_agent = user_agent
        self.headless = headless
        self.timeout = timeout
        self.driver = None
    
    def _setup_driver(self):
        """Setup Chrome WebDriver with appropriate options."""
        chrome_options = Options()
        
        if self.headless:
            chrome_options.add_argument('--headless')
        
        # Modern browser options
        chrome_options.add_argument(f'--user-agent={self.user_agent}')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        chrome_options.add_argument('--disable-images')  # Speed up loading
        # Enable JS for rendering dynamic pages (do not disable JavaScript)
        chrome_options.add_argument('--window-size=1920,1080')
        
        # Anti-detection options
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            # Execute script to remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            return True
        except WebDriverException as e:
            log.error('Failed to setup Chrome WebDriver: {error}', error=str(e))
            return False
    
    def download_page(self, url):
        """
        Download a page with JavaScript rendering.
        Returns (html_content, success, error_message)
        """
        if not self.driver:
            if not self._setup_driver():
                return None, False, "Failed to setup WebDriver"
        
        try:
            log.info('Loading URL with JavaScript: {url}', url=url)
            self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Additional wait for JavaScript to execute
            time.sleep(2)
            
            # Get the page source after JavaScript execution
            html_content = self.driver.page_source
            
            log.info('Successfully loaded page: {url} ({size} bytes)', 
                    url=url, size=len(html_content))
            
            return html_content, True, None
            
        except TimeoutException:
            error_msg = f"Timeout loading {url} after {self.timeout} seconds"
            log.warn(error_msg)
            return None, False, error_msg
            
        except WebDriverException as e:
            error_msg = f"WebDriver error loading {url}: {str(e)}"
            log.error(error_msg)
            return None, False, error_msg
            
        except Exception as e:
            error_msg = f"Unexpected error loading {url}: {str(e)}"
            log.error(error_msg)
            return None, False, error_msg
    
    def close(self):
        """Close the WebDriver."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

# Global instance for reuse
_js_downloader = None

def get_js_downloader(user_agent, headless=True, timeout=30):
    """Get or create a global JS downloader instance."""
    global _js_downloader
    if _js_downloader is None:
        _js_downloader = JSEnabledDownloader(user_agent, headless, timeout)
    return _js_downloader

def cleanup_js_downloader():
    """Cleanup the global JS downloader."""
    global _js_downloader
    if _js_downloader:
        _js_downloader.close()
        _js_downloader = None
