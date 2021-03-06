#!/usr/bin/env python3
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
import logging
import logging.config
import configparser
import os
import signal
import argparse
import collections
import threading

from lib.sewn_parser import SEWNParser
from lib.sewn_parser_rss import SEWNParserRSS
from lib.sewn_parser_xml import SEWNParserXML
from lib.sewn_parser_reddit import SEWNParserReddit
from lib.sewn_parser_gmane import SEWNParserGMANE
from lib.sewn_parser_atom import SEWNParserAtom
import lib.sewn_exceptions as SEWNExceptions


class SecurityWatchNotifier(object):
    CONFIG = os.getcwd() + '/config/sewn.ini'
    SOURCES = os.getcwd() + '/config/sewn-sources.ini'
    CONFIG_LOG = os.getcwd() + '/config/sewn-log.ini'

    def __init__(self, args):
        self.args = args
        self.cfg = self.read_config()
        self.sources = self.read_sources()
        self.logger = self.setup_logging()
        self.barrier = threading.Barrier(len(self.sources.sections()))
        self.semaphore = threading.Semaphore(1)
        self.event = threading.Event()
        self.articles = collections.deque(maxlen=1000)

        self.sewn_parser = SEWNParser(self.cfg, self.logger, self.articles, self.event)
        self.sewn_parser_rss = SEWNParserRSS(self.cfg, self.logger, self.articles, self.event)
        self.sewn_parser_xml = SEWNParserXML(self.cfg, self.logger, self.articles, self.event)
        self.sewn_parser_reddit = SEWNParserReddit(self.cfg, self.logger, self.articles, self.event)
        self.sewn_parser_gmane = SEWNParserGMANE(self.cfg, self.logger, self.articles, self.event)
        self.sewn_parser_atom = SEWNParserAtom(self.cfg, self.logger, self.articles, self.event)

        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)

    def setup_logging(self):
        logging.config.fileConfig(self.CONFIG_LOG)
        logger = logging.getLogger()
        if self.args['verbose']:
            logger.setLevel(logging.INFO)
        if self.args['debug']:
            logger.setLevel(logging.DEBUG)
        return logger

    def read_config(self):
        try:
            cfg = configparser.ConfigParser(allow_no_value=True)
            cfg.read(self.CONFIG)
            return cfg
        except (configparser.Error, IOError) as err:
            self.logger.error("Failed reading config file: %s" % err)
            raise SystemExit(1)

    def read_sources(self):
        try:
            cfg = configparser.ConfigParser()
            cfg.read(self.SOURCES)
            return cfg
        except (configparser.Error, IOError) as err:
            self.logger.error("Failed reading sources file: %s" % err)
            raise SystemExit(1)

    def run(self):
        for source in self.sources.sections():
            feed = self.sources.get(source, 'feed')
            next_check = self.sources.getint(source, 'check_interval')
            identify = self.sources.getboolean(source, 'identify')

            try:
                keywords = self.sources.get(source, 'keywords').split(',')
            except configparser.NoOptionError:
                keywords = None

            if self.sources.get(source, 'type') == 'rss':
                parser = self.sewn_parser_rss
            elif self.sources.get(source, 'type') == 'xml':
                parser = self.sewn_parser_xml
            elif self.sources.get(source, 'type') == 'reddit':
                parser = self.sewn_parser_reddit
            elif self.sources.get(source, 'type') == 'gmane':
                parser = self.sewn_parser_gmane
            elif self.sources.get(source, 'type') == 'atom':
                parser = self.sewn_parser_atom
            else:
                continue

            t = threading.Thread(target=self.parse_sources,
                                 args=(parser, source, feed, keywords, next_check, identify),
                                 name=source)
            t.start()
            self.logger.debug("Active threads (run): %d", threading.active_count())

    def parse_sources(self, parser, source, feed, keywords, next_check, identify):
        try:
            """
            articles -> tuple(source, title, link)
            """
            self.logger.debug("Parsing: %s", threading.current_thread())

            articles = parser.parse(source, feed, keywords, next_check, identify)
            new_articles = [art for art in articles if parser.is_new(art[1])]

            for source, title, link in new_articles:
                # Throttle, one source at a time to properly print at first run,
                # and group notifications from same source in subsequent runs.
                self.semaphore.acquire()
                self.logger.info("NEW: [%s] | %s | %s" %
                                 (source, title.strip(), link.strip()))
                if not SEWNParser.first_run:
                    parser.notify(source, link, title)
                self.semaphore.release()

                # Add article to history (thread-safe deque)
                parser.add_article(title)

            # Do first run no-notify to avoid spamming.
            if SEWNParser.first_run:
                self.logger.debug("First run: %s | Waiting at barrier: %d ",
                                  threading.current_thread(), self.barrier.n_waiting)
                thread_no = self.barrier.wait()
                # All threads at barrier after first run, thread 0 set False.
                if thread_no == 0:
                    SEWNParser.first_run = False
                self.logger.debug("Passed barrier: %s", threading.current_thread())
                parser.start_scheduler(next_check, self.parse_sources,
                                       (parser, source, feed, keywords, next_check, identify))
            else:
                parser.next_check_feed(next_check, self.parse_sources,
                                       (parser, source, feed, keywords, next_check, identify))

        except SEWNExceptions.ArticleParseFailed as err:
            self.logger.error("Failed parsing feed: %s (%s)" % (err.source, err.message))
            parser.next_check_feed(next_check, self.parse_sources,
                                   (parser, source, feed, keywords, next_check, identify))

    def cleanup(self, signo, frame):
        print("sewn.py shutting down..")

        # Notify thread and skip the next check if before next_datetime
        self.event.set()

        # Join all non-main threads
        thread_main = threading.current_thread()
        for thread in threading.enumerate():
            if thread is thread_main:
                continue
            thread.join()
            self.logger.debug("joined thread: %s" % thread.getName())
        raise SystemExit(0)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action='store_true', help="Display extra information.")
    parser.add_argument("--debug", action='store_true', help="Display debug information.")
    return vars(parser.parse_args())

def main():
    if not os.path.exists('logs'):
        os.mkdir('logs')
    args = parse_args()
    security_watch_notifier = SecurityWatchNotifier(args)
    security_watch_notifier.run()
    # Pause main thread after worker threads have been started.
    # Wait for signal and handle shutdown.
    signal.pause()

if __name__ == '__main__':
    main()
