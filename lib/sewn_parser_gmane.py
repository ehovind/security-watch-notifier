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
from lxml import etree
from lib.sewn_parser import SEWNParser
import lib.sewn_exceptions as SEWNExceptions

class SEWNParserGMANE(SEWNParser):

    def parse(self, source, feed, keyword, next_check):
        new_posts = list()

        doc = super().load_rss_feed(feed)

        try:
            ns = {"purl": "http://purl.org/rss/1.0/"}
            for article in doc.iterfind('purl:item', namespaces=ns):
                title = article.findtext("purl:title", namespaces=ns)
                link = article.findtext("purl:link", namespaces=ns)
                # If keyword is defined, only add selected articles
                if keyword and not title.startswith(keyword):
                    continue
                new_posts.append((source, super().sanitize(title), link))
        except (AttributeError, etree.XMLSyntaxError) as err:
            raise SEWNExceptions.ArticleParseFailed(source, err)

        return new_posts
