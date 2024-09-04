import math, re

def discover():
    string=""
    string2=""
    for i in range(2740):
        filename = "BenchmarkJava/BenchmarkTest0" + (3-math.floor((math.log10(i+1))))*"0" + str(i+1) + ".java"
        file = open(filename)
        r = file.read()
        countMA = len(re.findall('.*setMaxAge.*', r))
        s = re.findall('.*setSecure.*', r)
        st = re.findall('.*setSecure\(true\).*', r)
        sf = re.findall('.*setSecure\(false\).*', r)
        countS = len(s)
        countC = len(re.findall(".*javax.servlet.http.Cookie [_a-zA-Z][_a-zA-Z0-9]* =( |\n\s*)new.*", r))
        
        if countC!=0:
            if ((countC!=countMA or countC!=countS) or len(sf)!=0):
                string += filename+": " + str(countC) + "(Cookies) " + str(countMA) + "(MaxAge) " + str(countS) + "(Secure) " + str(len(sf)) + " is Secure=False and " + str(len(st)) + " is Secure=True \n"
            else:
                string2 += filename+": " + str(countC) + "(Cookies) " + str(countMA) + "(MaxAge) " + str(countS) + "(Secure) " + str(len(sf)) + " is Secure=False and " + str(len(st)) + " is Secure=True \n"

    file = open("../tools_result/result_vuln_cookie.txt", "w")
    file.write(string)
    file2 = open("../tools_result/result_nonvuln_cookie.txt", "w")
    file2.write(string2)

if __name__=="__main__":
    discover()