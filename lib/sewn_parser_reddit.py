"""
This file is part of Security Watch Notifier (sewn.py).
Copyright (C) 2015 Espen Hovind <espehov@ifi.uio.no>

sewn.py is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sewn.py is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sewn.py.  If not, see <http://www.gnu.org/licenses/>.
"""
import requests
from lib.sewn_parser import SEWNParser
import lib.sewn_exceptions as SEWNExceptions

class SEWNParserReddit(SEWNParser):

    REDDIT = 'https://www.reddit.com'

    def __init__(self, cfg, logger, articles, event):
        super().__init__(cfg, logger, articles, event)
        self.from_user = cfg.get('reddit', 'from')
        self.user_agent = cfg.get('main', 'user_agent')

    def load_rss_feed(self, feed, identify):
        try:
            if identify:
                headers = {'From': self.from_user,
                           'User-Agent': self.user_agent}
            else:
                headers = None
            self.logger.info("Loading Reddit feed: %s", feed)
            response = requests.get(feed, headers=headers)
            self.logger.debug("feed: %s | headers: %s" % (feed, response.headers))
            return response.json()
        except (IOError, ValueError) as err:
            self.logger.error("Failed loading reddit feed: %s" % err)
            return None

    def parse(self, source, feed, keywords, next_check, identify):
        """
        Load feed and parse articles to find title and link.
        If keyword is defined, only add selected articles.
        """
        new_posts = list()
        data = self.load_rss_feed(feed, identify)

        try:
            for submission in (data['data']['children']):
                title = submission['data']['title']
                link = submission['data']['permalink']
                if keywords and not super().check_keyword(title, keywords):
                    continue
                new_posts.append((source, super().sanitize(title), "%s%s" % (self.REDDIT, link)))
        except (AttributeError, KeyError, TypeError) as err:
            raise SEWNExceptions.ArticleParseFailed(source, err)

        return new_posts
