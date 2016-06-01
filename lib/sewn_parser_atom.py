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

class SEWNParserAtom(SEWNParser):

    def parse(self, source, feed, keywords, next_check, identify):
        """
        Load feed and parse articles to find title and link.
        If keyword is defined, only add selected articles.
        """
        new_posts = list()
        doc = super().load_feed(feed, identify)

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        try:
            for article in doc.iterfind("atom:entry", namespaces=ns):
                title = article.findtext("atom:title", namespaces=ns)
                link = article.find(".//atom:link[@rel='alternate']", namespaces=ns).get('href')
                if keywords and not super().check_keyword(title, keywords):
                    continue
                new_posts.append((source, super().sanitize(title), link))
        except (AttributeError, etree.XMLSyntaxError) as err:
            raise SEWNExceptions.ArticleParseFailed(source, err)

        return new_posts
