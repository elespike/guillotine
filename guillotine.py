from ConfigParser import SafeConfigParser
from burp         import IBurpExtender, IExtensionStateListener
from java.io      import File
from os           import path
from time         import sleep, time


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()

        self.callbacks.setExtensionName('Guillotine')

        self.callbacks.registerExtensionStateListener(self)

        self.unloaded = False
        self.scan_queue_items = []
        self.queue_items_left = []

        # TODO check paths, make sure all are writable

        self.config = SafeConfigParser()
        config_path = path.join(
            path.dirname(self.callbacks.getExtensionFilename()),
            'guillotine.config'
        )
        self.config.read(config_path)

        log_path = self.config.get('Log', 'Full path')
        if path.isdir(path.dirname(log_path)):
            try:
                log_file = open(log_path, 'w')
            except IOError as e:
                # TODO log actual failure
                print(e)
            else:
                # TODO set logging output to file
                # TODO will logging automatically close the file?
                pass

        if self.config.getboolean('Extension', 'Auto start'):
            self.queue_site_map()
        else:
            # TODO print usage text describing that a project file with scope already set is required
            # and that Guillotine will scan the entire - scoped - site map.
            # TODO document the need for --unpause-spider-and-scanner
            pass

        while not self.unloaded and not self.queue_done():
            sleep(1)

        # TODO document that it will exit without prompt in headless mode.
        prompt_user = True
        # This callback exits without prompt when running headless.
        self.callbacks.exitSuite(prompt_user)

    def queue_site_map(self):
        site_map = self.callbacks.getSiteMap(None)

        for request_response in site_map:
            request_info = self.helpers.analyzeRequest(request_response)
            http_service = request_response.getHttpService()

            if self.callbacks.isInScope(request_info.getUrl()):
                scan_queue_item = self.callbacks.doActiveScan(
                    http_service.getHost(),
                    http_service.getPort(),
                    http_service.getProtocol() == 'https',
                    request_response.getRequest()
                )
                self.scan_queue_items.append(scan_queue_item)
        self.queue_items_left = list(self.scan_queue_items)

    def queue_done(self):
        done_states = [
            'finished' ,
            'cancelled',
            'abandoned',
        ]

        queue_items_left = list(self.queue_items_left)
        for scan_queue_item in queue_items_left:
            status = scan_queue_item.getStatus().lower()
            if all([not status.startswith(done_state) for done_state in done_states]):
                return False
            self.queue_items_left.remove(scan_queue_item)

        return True

    def generate_report(self):
        # TODO log number of errors for each scanqueueitem
        report_path = self.config.get('Report', 'Full path')
        if not path.isdir(path.dirname(report_path)):
            report_path = path.join(
                path.dirname(self.callbacks.getExtensionFilename()),
                'guillotine_{}.html'.format(int(time()))
            )
        all_issues = []
        for scan_queue_item in self.scan_queue_items:
            all_issues.extend(scan_queue_item.getIssues())
        # TODO what happens with 0 findings?
        # if all_issues:
        # TODO what happens if file isn't writable?
        self.callbacks.generateScanReport('html', all_issues, File(report_path))

    def extensionUnloaded(self):
        # Will be called either if the extension is manually unloaded,
        # or when Burp Suite exits - headless or not.
        self.generate_report()
        self.unloaded = True
