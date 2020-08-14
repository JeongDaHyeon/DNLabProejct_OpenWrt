import re

# regular expression to search domain name
regex_domain_name = re.compile('[\w]+\.(com|net|co.kr)')

if __name__ == '__main__':
    domain_name = regex_domain_name.search('m.naver.com')
    if domain_name:
        print(domain_name.group())
