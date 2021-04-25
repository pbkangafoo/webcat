# webcat
 simple file and directory scanner for websites

## What is webcat?

webcat is a simple files and directories scanner for websites using an external file as source for files / directories. It was written for a pentesting class therefore it was kept simple to perform some testings on a potential vulnerable webserver. It might get improved in the future.

## Webcat usage

For starting a scan on a certain target just displaying found files:

> python webcat.py -t http://sitetoscan.com -f scanlist.txt

## Screenshot

![Screenshot](https://github.com/pbkangafoo/webcat/blob/main/webcat_screenshot.jpg "webcat screenshot")
