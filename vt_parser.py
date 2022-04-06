from aiohttp import ClientSession
import asyncio
from collections import namedtuple
import os
import re

HEADER = "\033[95m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
WARNING = "\033[93m"
FAIL = "\033[91m"
END = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

Query = namedtuple('Query', 'line query')
Result = namedtuple('Result', 'type associated query vt_json')


class VT_Parser:
    """
    This is an abstract class.
    Classes that extend VT_Parser should implement the get_queries method.
    """

    def __init__(self, name, filename, keys, known_good="known_good.txt"):
        self.name = name
        self.filename = filename
        self.keys = keys
        self.known_fp = known_good
        self.known = self.load_known_list()
        self.queries = []
        self.results = []

    def get_queries(self):
        pass

    def load_known_list(self):
        s = set()
        with open(self.known_fp) as f:
            for line in f.readlines():
                s.add(line.strip())
        return s

    async def search_vt(self, query, key, session):
        headers = {'x-apikey': key}
        url = f'https://www.virustotal.com/api/v3/search?query={query.query}'
        res = await session.request(method='GET', url=url, headers=headers)
        if res.status == 429:
            print("limited, try again tomorrow :(")
            return
        
        res = await res.json()

        if res['data']:
            self.results.append(Result(
                type='artifact',
                query=query.query,
                vt_json=res,
                associated=query.line,
            ))
        else:
            print(f"No results for {query.query}")

    async def vt(self):
        async with ClientSession() as session:
            await asyncio.gather(*[
                self.search_vt(q, next(self.keys), session)
                for q in self.queries
            ])

        self.results.sort(key=lambda x: x.vt_json['data'][0]['attributes']
                          ['last_analysis_stats']['malicious'], reverse=True)

    def run(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.vt())

    ##### OUTPUT #####
    def get_header(self):
        return f'--- {self.filename} | {self.name} Analysis --- | {len(self.results)} queries checked'

    def get_analysis_string(self, analysis):
        allowed_keys = ['malicious', 'harmless', 'suspicious', 'undetected']
        return " | ".join([f"{k}: {v}" for k, v in analysis.items() if k in allowed_keys])

    def print_res(self, results, verbose):
        for res in results:
            attributes = res.vt_json['data'][0]['attributes']
            analysis = attributes['last_analysis_stats']
            mal = analysis['malicious']
            harmless = analysis['harmless']

            color = GREEN if mal == 0 else FAIL if mal > harmless else WARNING
            if color != GREEN:
                print(
                    f' {color}Query: {res.query} ')
                if verbose:
                    print(f'Line: {res.associated}')
                print(
                    f'    {self.get_analysis_string(analysis)}\n', END)

    def pprint(self, verbose):
        print(f'\n{BOLD}' + self.get_header())
        self.print_res(self.results, verbose)

    def save_results(self, results, f, verbose):
        for res in results:
            analysis = res.vt_json['data'][0]['attributes']['last_analysis_stats']
            f.write(
                f' Query: {res.query}')
            if verbose:
                f.write(f'Line: {res.associated}')
            f.write(
                f'    {self.get_analysis_string(analysis)}\n')

    def save_out(self, fn):
        l = 'a' if os.path.exists(fn) else 'w'
        with open(fn, l) as f:
            f.write(self.get_header() + '\n')
            self.save_results(self.results, f)
            f.write('\n')

    ##### POST PROCCESS #####
    def post_process(self):
        s = set()
        with open(self.known_fp, 'a') as f:
            for res in self.results:
                attributes = res.vt_json['data'][0]['attributes']
                analysis = attributes['last_analysis_stats']
                mal = analysis['malicious']

                if mal == 0 and res.query not in s and res.query not in self.known:
                    f.write(res.query + "\n")
                    s.add(res.query)


class VT_Hashes(VT_Parser):
    def __init__(self, *args):
        super().__init__("HASH", *args)
        self.get_queries()
        self.run()

    def get_queries(self):
        with open(self.filename, 'r') as f:
            for line in f:
                # MD5
                hashes = re.findall(
                    r'[a-f0-9]{32}', line, re.IGNORECASE)

                # sha1
                hashes += re.findall(r'[a-f0-9]{40}', line, re.IGNORECASE)

                # sha256
                hashes += re.findall(r'[a-f0-9]{64}', line, re.IGNORECASE) 

                for h in hashes:
                    if h and h not in self.known:
                        self.queries.append( Query(
                            line=line,
                            query=h,
                        ) )


class VT_URL(VT_Parser):
    def __init__(self, *args):
        super().__init__("URL", *args)
        self.get_queries()
        self.run()

    def get_queries(self):
        with open(self.filename, 'r') as f:
            for line in f:
                # Won't find anything without http or https
                regex = re.compile(
                    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|(([^\s()<>]+|(([^\s()<>]+)))))+(?:(([^\s()<>]+|(([^\s()<>]+))))|[^\s`!()[]{};:'\".,<>?«»“”‘’]))"
                )
                urls = re.findall(regex, line)
                for url in urls:
                    if url and url not in self.known:
                        self.queries.append( Query(
                            line=line,
                            query=url[0],
                        ) )

class VT_IPv4(VT_Parser):
    def __init__(self, *args):
        super().__init__("IPs", *args)
        self.get_queries()
        self.run()

    def get_queries(self):
        with open(self.filename, 'r') as f:
            for line in f:
                ips = re.findall(
                    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])){3}', 
                    line )
                for ip in ips:
                    if ip and ip not in self.known:
                        self.queries.append( Query(
                            line=line,
                            query=ip,
                        ) )
