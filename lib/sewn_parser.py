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
import urllib
from lxml import etree
import time
import sched
import dbus
import jinja2
import datetime
import unicodedata

class SEWNParser(object):
    first_run = True
    sched_priority = 1

    def __init__(self, cfg, logger, articles, event):
        self.cfg = cfg
        self.logger = logger
        self.articles = articles
        self.event = event

        self.parser = self.init_parser()
        self.notifier = self.init_notifier()
        self.scheduler = self.init_scheduler()

    def init_parser(self):
        return etree.XMLParser(ns_clean=False, recover=True)

    def init_scheduler(self):
        return sched.scheduler(time.time, time.sleep)

    def start_scheduler(self, next_check, func, *args):
        self.logger.debug("Starting scheduler, next check in %s seconds (%s)", next_check, args)
        self.scheduler.enter(next_check, self.sched_priority, func, *args)

        # Run the scheduled event. If shutdown event is set during wait,
        # unblock and since run() event is execute before check, it is skipped.
        self.event.wait(next_check)
        self.scheduler.run(blocking=False)
        self.event.clear()

    def init_notifier(self):
        try:
            bus = dbus.SessionBus()
            notify_proxy = bus.get_object(self.cfg.get('dbus', 'item'),
                                          self.cfg.get('dbus', 'path'))
            return dbus.Interface(notify_proxy, self.cfg.get('dbus', 'interface'))
        except dbus.exceptions.DBusException as err:
            self.logger.error("Failed dbus setup: %s" % err)

    def load_feed(self, feed, identify=False):
        try:
            request = urllib.request.Request(feed)
            if identify:
                request.add_header('From', self.cfg.get('main', 'from'))
                request.add_header('User-Agent', self.cfg.get('main', 'user_agent'))
            self.logger.info("Loading feed: %s", feed)
            response = urllib.request.urlopen(request)
            self.logger.debug("feed: %s | headers: %s" % (feed, response.info()._headers))
            return etree.parse(response, self.parser)
        except (IOError, etree.XMLSyntaxError) as err:
            self.logger.error("Failed loading feed: %s (%s)" % (feed, err))
            return None

    def check_keyword(self, title, keywords):
        return any(keyword.lower() in title.lower() for keyword in keywords)

    def is_new(self, title):
        """ Check if article is never before seen. """
        if not self.articles:
            return True
        return title not in self.articles

    def add_article(self, title):
        self.articles.append(title)

    def sanitize(self, title):
        # Remap white space and carriage return
        remap = {ord('\t'): ' ',
                 ord('\f'): ' ',
                 ord('\r'): None,
                 ord('\n'): None}

        # Normalize unicode
        return unicodedata.normalize('NFC', title.translate(remap))

    def next_check_feed(self, next_check, func, *args):
        time_now = datetime.datetime.now()
        next_datetime = time_now + datetime.timedelta(seconds=next_check)
        self.logger.debug("Next check at: %s (%s)",
                          next_datetime.strftime('%Y-%m-%d %H:%M:%S'), args)

        # Schedule another check at next_datetime
        self.scheduler.enter(next_check, self.sched_priority, func, *args)

        # Run the scheduled event. If shutdown event is set during wait,
        # unblock and skip run.
        self.event.wait(next_check)
        self.event.clear()

    def notify(self, source, link, title, actions=[], hints={}):
        """
        Method signature: https://developer.gnome.org/notification-spec/
        """
        # Require user to acknowledge selected Security news
        keywords = self.cfg.get('main', 'ack_keywords').split(',')
        if any(keyword.lower() in title.lower() for keyword in keywords):
            hints = {'urgency': dbus.Byte(2)}
            actions = ['0', 'Acknowledge']
        else:
            hints = {'urgency': dbus.Byte(1)}

        try:
            env = jinja2.Environment(loader=jinja2.PackageLoader('sewn', 'templates'))
            template = env.get_template('notification.jin')
            message = template.render(data=(source, title, link))
            summary = message.splitlines()[0]
            description = '\r'.join(message.splitlines()[1:])

            self.notifier.Notify(self.cfg.get('dbus', 'app_name'), dbus.UInt32(0),
                                 self.cfg.get('dbus', 'app_icon'), summary, description,
                                 actions, hints, self.cfg.getint('dbus', 'timeout'))
            # Throttle notifications
            time.sleep(self.cfg.getint('dbus', 'delay'))
        except jinja2.TemplateError as err:
            self.logger.error("Failed constructing message: %s" % err)
        except dbus.exceptions.DBusException as err:
            self.logger.error("Failed sending notification: %s" % err)
