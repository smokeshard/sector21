# Basic OSINT Scraping Script
# Author: @smokeshard on Discord
# ======================================================================================================================

import http.client
import re
import urllib.parse

def ensureSubdomain(resource):
    resource = resource.strip()
    resourceParsed = urllib.parse.urlparse(resource)
    resourceHostname = resourceParsed.hostname
    if resourceHostname and resourceHostname.count(".") == 1:
        resourceHostname = "www." + resourceHostname
        resourceNetLoc = resourceHostname + (":" + str(resourceParsed.port) if resourceParsed.port else "")
        resource = urllib.parse.urlunparse((
            resourceParsed.scheme,
            resourceNetLoc, 
            resourceParsed.path, 
            resourceParsed.params, 
            resourceParsed.query, 
            resourceParsed.fragment
        ))
        return resource
    else:
        return resource

def fetchHTML(resource):
    resourceParsed = urllib.parse.urlparse(resource)
    resourceConnection = http.client.HTTPSConnection(resourceParsed.netloc, timeout = 30)
    try:
        resourceConnection.request("GET", resourceParsed.path if resourceParsed.path else "/")
        resourceResponse = resourceConnection.getresponse()
        if resourceResponse.status == 200:
            return resourceResponse.read().decode("utf-8", errors="ignore")
        else:
            print(f"[ERR.] '{resource}' was not able to be fetched (Status Code {resourceResponse.status}).")
    except Exception as e:
        print(f"[ERR.] '{resource}' was not able to be fetched ({e}).")
    finally:
        resourceConnection.close()
    return ""

def extractLinks(source):
    return re.findall(r"href=[\"'](https?://[^\s\"'<>]+)[\"']", source)

def extractEmails(source):
    return re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", source)

def extractNumbers(source):
    return re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:?\d{2,4}?[-.\s]?)\d{3}[-.\s]?\d{4}\b", source)

def extractContent(source):
    return re.sub(r"<[^>]+>", " ", source).strip()

if __name__ == "__main__":
    resource = input("Enter a URL to start scraping: ")
    if not resource.startswith("http"):
        resource = "http://" + resource
    resource = ensureSubdomain(resource)
    source = fetchHTML(resource)
    if source:
        print("\nExtracted URLs: ")
        for link in extractLinks(source):
            print(link)
        print("\nExtracted Email Addresses: ")
        for email in extractEmails(source):
            print(email)
        print("\nExtracted Phone Numbers: ")
        for number in extractNumbers(source):
            print(number)
        print("\n\n=====\n\nPreview of Page Text\n\n=====\n")
        print(extractContent(source)[:500])

