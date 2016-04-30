#THIS STRING IS SO THAT PWNBOT DOES NOT DOWNLOAD ITSELF DO NOT DELETE
#-*- coding: utf-8 -*-
#ROPgadget written by salwan, libc fingerprinter, checksec.sh slimm609, libc database niklasb, https://github.com/stamparm/DSSS and https://github.com/stamparm/DSXS
#ROPgadget: look for notable ROP gadgets and list them (e.g. pop esp)
#Checksec: check for exploit mitigations
#libc fingerprinter + libc database: give a libc version number when supplied an example offset and function name
#85a471229b705a3cd3db22499a0bc8acc8d8b4fd
import time, json, copy, datetime, requests, re, wget, hashlib, binascii, os, logging, shutil, tarfile, zipfile
from slackclient import SlackClient
from subprocess import check_output
from yelpapi import YelpAPI
from bs4 import BeautifulSoup
from random import randint

class Choice(object):
    def __init__(self, name=None, url=None, rating=None, img_url = None, categories=None,
                 address=None, phone=None, pricing=None):
        self.name = name
        self.votes = 0
        self.url = url
        self.rating = rating
        self.img_url = img_url
        self.categories = categories
        self.address = address
        self.phone = phone
        self.pricing = pricing

    def build_attachment(self):
        data = {}
        data["fallback"] = self.name
        data["title"] = self.name
        if self.url.startswith("http://www.yelp.com/") or self.url.startswith("https://www.yelp.com/") \
            or self.url.startswith("http://yelp.com/") or self.url.startswith("https://yelp.com/"):
            data["title_link"] = self.url
        data["text"] = "Located at *{0}*\n*Phone: * {1}\n*Pricing: * {2}".format(self.address, self.phone, self.pricing)
        data["fields"] = []
        if self.categories:
            categories = {}
            categories["title"] = "Categories"
            cats = "\n".join([c[0] for c in self.categories])
            categories["value"] = cats
            categories["short"] = True
            data["fields"].append(categories)
        if self.rating:
            rating = {}
            rating["title"] = "Rating"
            rating["value"] = str(self.rating)+"/5"
            rating["short"] = True
            data["fields"].append(rating)
        data["mrkdwn_in"] = ["text"]
        if self.img_url:
            data["thumb_url"] = self.img_url
        return data

class FileExists(Exception):
    x = 0

#returns the file list without the md5 hashes
def get_filelist():
    global current_dir
    with open(current_dir+"filelist.txt", "r") as f:
        rawlist = (f.read()).split("\n")
        x = 0
        filelist = []
        while x < len(rawlist):
            if x%2==0:
                filelist.append(rawlist[x])
            x+=1
        return filelist

def get_whitelist():
    with open("whitelist.txt", "r") as whitelist:
        raw = whitelist.read()
        return raw.split("\n")

#http://stackoverflow.com/questions/3431825/generating-a-md5-checksum-of-a-file
def md5(afile, hasher=hashlib.md5(), blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return binascii.hexlify(hasher.digest())

def split_msg(msg):
    s = msg.partition(" ")
    return s[0].strip(), s[2].strip()

def process_text(text):
    text = text.strip()
    text = (c for c in text if 0 < ord(c) < 127)
    text = ''.join(text)
    text = re.sub(r'([^\s\w]|_)+', '', text)
    return text

def traverse_dir(working_dir):
    dir_tree = os.walk(working_dir)
    ret_str = "```"
    for path in dir_tree:
        working_dir = path[0]
        for fle in path[2]:
            ret_str += "\npath: "
            ret_str += check_output(["file", working_dir+"/"+fle])
            ret_str += "-----------------"
    ret_str += "```"
    return ret_str

def send_msg(txt, cnl):
    sc.api_call("chat.postMessage", channel=cnl, text=txt, username=USERNAME)

def get_key(item):
    return item.votes

def get_name(sc, user):
    global USERS
    if user not in USERS.keys():
        response = json.loads(sc.api_call("users.info", user=user))
        name = response["user"]["name"]
        USERS[user] = name
    return USERS[user]

def post_attachment(txt, cnl, att):
    params = {}
    params["token"] = token
    params["text"] = txt
    params["channel"] = cnl
    params["username"] = USERNAME
    params["attachments"] = json.dumps(att)
    response = requests.post("https://slack.com/api/chat.postMessage", params=params)
    logging.info(response.content)

def upload_file(cnl, content, fn, title):
    files = {"file": content}
    channel = []
    channel.append(cnl)
    params = {}
    params["token"] = token
    params["channels"] = channel
    params["username"] = USERNAME
    params["filename"] = fn
    params["title"] = title
    response = requests.post("https://slack.com/api/files.upload", params=params, files=files)
    return response.content

def get_yelp_results(term):
    global yelp
    response = yelp.search_query(term=term, location=LOCATION)
    return response

def build_choice(business_dict):
    name = None
    url = None
    rating = None
    img_url = None
    categories = None
    address = None
    phone = None
    if "name" in business_dict.keys():
        name = business_dict["name"]
    if "url" in business_dict.keys():
        url = business_dict["url"]
    if "rating" in business_dict.keys():
        rating = business_dict["rating"]
    if "image_url" in business_dict.keys():
        img_url = business_dict["image_url"]
    if "categories" in business_dict.keys():
        categories = business_dict["categories"]
    if "location" in business_dict.keys():
        if "address" in business_dict["location"].keys():
            if len(business_dict["location"]["address"])!=0:
                address = business_dict["location"]["address"][0]
    if "display_phone" in business_dict.keys():
        phone = business_dict["display_phone"]
    elif "phone" in business_dict.keys():
        phone = business_dict["phone"]
    logging.info(name)
    logging.info(url)
    logging.info(rating)
    logging.info(img_url)
    logging.info(categories)
    logging.info(address)
    logging.info(phone)
    tmp = Choice(name, url, rating, img_url, categories, address, phone)
    return tmp

def get_pricing(term, indices=[0]):
    start_values = {}
    for i in indices:
        if (i/10) not in start_values.keys():
            start_values[i/10] = []
        start_values[i/10].append(i%10)
    #location of poly is hardcoded
    url = "http://www.yelp.com/search?find_desc={0}&find_loc=6+Metrotech+Ctr,+Brooklyn,+NY&start={1}"
    pricing_values = []
    for i in sorted(start_values.keys()):
        response = requests.get(url.format(term, i))
        soup = BeautifulSoup(response.content)
        results = soup.find_all("li", {"class": "regular-search-result"})
        for num in start_values[i]:
            result = results[i].find("span", {"class": "business-attribute price-range"})
            if result:
                pricing_values.append(result.string)
            else:
                pricing_values.append(None)
    logging.info(pricing_values)
    return pricing_values

def build_fr_term(term, result_numbers=[0]):
    response = get_yelp_results(term)
    if "businesses" in response.keys():
        businesses = response["businesses"]
        result = []
        if businesses:
            indices = []
            for num in result_numbers:
                if num<len(businesses):
                        tmp = build_choice(businesses[num])
                        result.append(tmp)
                        indices.append(num)
            pricing_values = get_pricing(term, indices)
            if len(pricing_values)==len(result):
                for i in range(len(result)):
                    result[i].pricing = pricing_values[i]
        else:
            tmp = Choice(name=term, url=term)
            result.append(tmp)
        if len(result)==1:
            return result[0]
        return result


#WIP
#def whitelist():
    #if type(data) == type({}):
        #channel = data["channel"]
        #l_file = open("whitelist.txt", "a")
        #wl_file.write(get_uid(data["data"]))
        #wl_file.close()

def clearfiles(sc, data):
    '''temp'''
    params = {"token": token, "channel": cnl}
    response = requests.post("https://slack.com/api/files.list", params=params)
    fileobj = response.content
    print fileobj
    #params = {"token": token, "filelid": fileid}
    #reponse = requests.post("https://slack.com/api/files.delete", params=params)
    fileid = fileobj[fileobj.find('"id":"')+6:]
    fileid = fileid[:fileid.find('"')]

 
def applause(sc, data):
    '''applaud travis goodspeed'''
    if type(data) == type({}):
        channel = data["channel"]
        f = open("applause.gif", "r")
        upload_file(channel, f, "applause.gif", "applause.gif")
        

def coinflip(sc, data):
    if type(data) == type({}):
        channel = data["channel"]
        try:
            _range = data["data"].split()
            result = randint(int(_range[0]), int(_range[1]))
            send_msg("Random number with bounds " + _range[0] + " to " + _range[1] + ": " + str(result), channel)
        except:
            send_msg("invalid input ", channel)

#to add: auto extraction/unzipping & recursive directory exploration, bulk analysis when ctfmode, stat, all the tools at the top, file type specific analysis, like fscheck, pngcheck, stegsolve(?), 
def analyze(sc, data): #WIP
    """Usage: !analyze <filename>. Gives useful data about a binary file"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            #if data["data"] allow directory specific commands
            global current_dir
            dir_contents = ""
            filename = data["data"]
            if filename in get_filelist():
                outstring = "```"
                file_out = check_output(["file", current_dir+filename])
                outstring += file_out + "\n======================\n"
                filetype = file_out[len(current_dir+filename)+2:file_out.find(",")]
                if filetype == "gzip compressed data" or filetype == "POSIX tar archive (GNU)" or filetype == "Zip archive data":
                    send_msg("attempting to decompress archive", channel)
                    if filetype == "gzip compressed data" or filetype == "POSIX tar archive (GNU)":
                        tar = tarfile.open(current_dir+filename)
                        tar.extractall(path=current_dir+filename+"_dir/")
                    else:
                        with zipfile.ZipFile(current_dir+filename, "r") as z:
                            z.extractall(current_dir+filename+"_dir/")
                        count = 0
                        tmpdir = os.walk("./broken_records_33.zip_dir")
                        for fle in tmpdir:
                            if fle[2] is not None:
                                filepath = fle[0]
                                count += 1
                    if count > 1:
                        dir_contents = traverse_dir(current_dir+filename+"_dir/")
                        shutil.rmtree(current_dir+filename+"_dir/")
                    elif count == 1:
                        newfile = os.listdir(current_dir+filename+"_dir/")[0]
                        send_msg("Single compressed file; replacing " + filename + " with " + newfile, channel)
                        os.rename(current_dir+"_dir/"+newfile, current_dir+newfile)
                        delete(sc, data)
                stat_out = check_output(["stat", current_dir+filename])
                outstring += stat_out[:stat_out.find("\nAccess: ")] + "\n======================\n"
                print stat_out
                binwalk_out = check_output(["binwalk", current_dir+filename])
                outstring += binwalk_out[:-1] + "```"
                if dir_contents == "":
                    send_msg(outstring, channel)
                else:
                    send_msg(dir_contents, channel)
            else:
                send_msg("File does not exist", channel)

def rename(sc, data):
    """Usage: !rename <filename> <new name>. Renames a file"""
    if type(data)==type({}):
        try:
            channel = data["channel"]
            global current_dir
            filelist = get_filelist()
            rawlist = open(current_dir+"filelist.txt", "r").read().split("\n")
            params = data["data"].split()
            if "/" in params[1] or params[1] in os.listdir(current_dir):
                raise Exception
            if params[0] in filelist and len(params)==2:
                os.rename(current_dir+params[0], current_dir+params[1])
                f = open(current_dir+"filelist.txt", "w")
                for raw in rawlist:
                    if raw == params[0]:
                        f.write(params[1] + "\n")
                    elif raw != "":
                        f.write(raw + "\n")
                send_msg("File sucessfully renamed to " + params[1], channel)
            elif len(params)==2:
                send_msg("Invalid parameters", channel)
            else:
                send_msg("File does not exist", channel)
        except: #to do: better exception handling
            send_msg("Invalid rename", channel)


#to add: pull down all challenges on a CTF page, add trello integration
def bin(sc, data):
    """Usage: !bin <download link>. Have pwnbot download a file from a link."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            url = (data["data"])[1:-1]
            logging.info(url)
            global current_dir
            try:
                global req_key
                if req_key:
                    r = requests.get(privurl, headers={'Authorization': 'Bearer '+token})
                    rname = data["filename"]
                    if r is None:
                        raise Exception
                    r = r.content
                    with open(current_dir+rname, "wb") as f:
                        f.write(r)
                    r = rname
                else:
                    r = wget.download(url)
                os.rename(r, current_dir+r)
                md5checksum = hashlib.md5(open(current_dir+r).read()).hexdigest()
                rawlist = (open(current_dir+"filelist.txt", "r").read()).split()
                if md5checksum in rawlist:
                    raise FileExists()
                f = open(current_dir+"filelist.txt", "a")
                f.write(r + "\n")
                f.write(md5checksum + "\n")
                f.close()
                if current_dir != "./":
                    send_msg("File "+ r + " downloaded successfully to group " + current_dir[1:], channel)
                else: 
                    send_msg("File" + r + " downloaded successfully", channel)
                logging.info("File downloaded successfully")
            except FileExists:
                logging.info("File already exists")
                existing = rawlist[rawlist.index(md5checksum)-1]
                send_msg("File already exists as " + existing, channel)
                os.remove(r)
            except:
                logging.info("couldnt find a downloadable file")
                send_msg("Couldn't find a downloadable file", channel)

def file_list(sc, data):
    """Usage: !filelist. Lists files."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            filelist = get_filelist()
            output = "```"
            for item in filelist:
                output += item + "\n"
            output = output[:-1] + "```"
            send_msg(output, channel)

def request(sc, data):
    """Usage: !request <filename>. Pwnbot uploads the requested file"""
    if type(data)==type({}):
        if "channel" in data.keys():
            global current_dir
            channel = data["channel"]
            filelist = get_filelist()
            rqfile = data["data"]
            if rqfile in filelist:
                with open(current_dir+rqfile, "rb") as f:
                    upload_file(channel, f, rqfile, rqfile)
                    logging.info("File uploaded")
            elif "CTF Folder: " + rqfile in filelist:
                shutil.make_archive(rqfile, "zip", rqfile)
                with open(rqfile+".zip", "r") as zipf:
                    upload_file(channel, zipf, rqfile + ".zip", rqfile + ".zip")
                    os.remove(rqfile+".zip")
            else:
                logging.info("File not found")
                send_msg("Could not find file", channel)

def delete(sc, data):
    """Usage: !delete <filename>. For deleting files that slackbot has downloaded"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            global current_dir
            f = open(current_dir+"filelist.txt", "r")
            slist = (f.read()).split("\n")
            f.close()
            if data["data"] in slist:
                f = open(current_dir+"filelist.txt", "w")
                md5flag = False
                for fil in slist:
                    if fil != data["data"] and md5flag == False:
                        f.write(fil + "\n")
                    elif not md5flag:
                        md5flag = True
                    else:
                        md5flag = False
                os.remove(current_dir+data["data"])
                send_msg("File " + data["data"] + " deleted", channel)
            else:
                send_msg("File not found", channel)

#to add: folder organization by CTF via !ctfmode <ctf name>
def ctfmode(sc, data):
    """Usage: !ctfmode <ctfname>. toggle ctfmode which allows creation of public files to pull down files without requiring links"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            global ctfmode
            global current_dir
            if "/" not in data["data"]: 
                ctfmode = not ctfmode
                current_dir ="./"
                if data["data"] != "" and ctfmode == True:
                    ctfname = process_text(data["data"])
                    if not os.path.exists(data["data"]):
                        os.mkdir(ctfname)
                        f = open(current_dir+"filelist.txt", "a")
                        f.write("CTF Folder: " + ctfname + "\n")
                        f.write("FOLDER\n")
                        f.close()
                    current_dir = ctfname+"/"
                    f = open(current_dir+"filelist.txt", "a")
                send_msg("ctfmode is set to " + str(ctfmode), channel)
            else:
                send_msg("forward slashes are not allowed in folder names", channel)
         
def gif(sc, data):
    """Usage: !gif <imgur search>. Imgur image search. leave blank for random (I think)."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            query = process_text(data["data"])
            url = "http://imgur.com/search/score?q=" #test+abc+ext%3Agif
            for word in query.split():
                url = url + word + "+"
            url = url + "ext%3Agif"
            soup = BeautifulSoup((requests.get(url)).text)
            results = soup.find_all("a", class_="image-list-link")
            imgurls = []
            for result in results:
                r = re.compile('href="/gallery(.*)"')
                ext = r.search(str(result)).group(1)
                imgurls.append("https://imgur.com" + ext + ".gif")
            logging.info(query)
            if len(imgurls) == 0:
                logging.info("no results")
                send_msg("No results", channel)
            elif len(imgurls) <= 10 or query == "":
                logging.info("not enough images, or catchall query")
                send_msg(imgurls[randint(0, len(imgurls)-1)], channel)
            else:
                send_msg(imgurls[randint(0, 10)], channel)


def rsvp(sc, data):
    """Usage: !rsvp. Indicate that you will be attending the event."""
    global ATTENDEES, USERS
    if type(data)==type({}):
        if ("user" in data.keys()) and ("channel" in data.keys()):
            if (data["user"]) and (type(data["user"]) in string_types) \
                and (data["channel"]) and (type(data["channel"]) in string_types):
                user = data["user"]
                channel = data["channel"]
                name = get_name(sc, user)
                msg = u""
                if user not in ATTENDEES:
                    ATTENDEES.append(user)
                    msg = u"{0} has RSVP'ed".format(name)
                else:
                    msg = u"{0} is already RSVP'ed".format(name)
                logging.info(msg)
                send_msg(msg, channel)

def dersvp(sc, data):
    """Usage: !dersvp. Remove name from list of attendees."""
    global ATTENDEES, USERS
    if type(data)==type({}):
        if ("user" in data.keys()) and ("channel" in data.keys()):
            if (data["user"]) and (type(data["user"]) in string_types) \
                and (data["channel"]) and (type(data["channel"]) in string_types):
                user = data["user"]
                channel = data["channel"]
                name = get_name(sc, user)
                msg = u""
                if user not in ATTENDEES:
                    msg = u"{0} is not RSVP'ed yet".format(name)
                else:
                    ATTENDEES.remove(user)
                    msg = u"{0} is no longer RSVP'ed".format(name)
                logging.info(msg)
                send_msg(msg, channel)

def vote(sc, data):
    """Usage: !vote <choice>. Cast your vote for choice. Choice can be an existing option's number as shown in !choices, choice name, or a new option."""
    global CHOICES, VOTES, USERS
    if type(data)==type({}):
        if ("user" in data.keys()) and ("data" in data.keys()) and ("channel" in data.keys()):
            if (data["data"]) and (type(data["data"]) in string_types) \
                and (data["user"]) and (type(data["user"]) in string_types) \
                and (data["channel"]) and (type(data["channel"]) in string_types):
                vote_for = process_text(data["data"])
                channel = data["channel"]
                if len(vote_for)>50:
                    msg = u"Restaurant name too long"
                    logging.info(msg)
                    send_msg(msg, channel)
                    return
                user = data["user"]
                index = -1
                try:
                    index = int(vote_for) - 1
                    if (index<len(CHOICES) and index>=0 and len(CHOICES)>0):
                        vote_for = CHOICES[index].name
                    else:
                        msg = "Not a valid choice."
                        send_msg(msg, channel)
                        return
                except:
                    tmp = build_fr_term(vote_for)
                    for ind, item in enumerate(CHOICES):
                        if tmp.url.lower()==item.url.lower():
                            index = ind
                            break
                    if index == -1:
                        CHOICES.append(tmp)
                        index = len(CHOICES)-1
                prev = -1
                if user in VOTES.keys():
                    prev = VOTES[user]
                name = get_name(sc, user)
                msg = u""
                if prev>-1:
                    if (CHOICES[prev]==CHOICES[index]):
                        msg = u"You're already voting for that option"
                    else:
                        CHOICES[prev].votes -= 1
                        CHOICES[index].votes += 1
                        msg = u"{0} changed vote from {1} to {2}".format(name, CHOICES[prev].name, CHOICES[index].name)
                        if CHOICES[prev].votes<1:
                            index-=1
                            for user in VOTES:
                                if VOTES[user]>prev:
                                    VOTES[user] -= 1
                            CHOICES.pop(prev)
                else:
                    CHOICES[index].votes += 1
                    msg = u"Vote recorded: {0} wants {1}".format(USERS[user], CHOICES[index].name)
                VOTES[user] = index
                logging.info(msg)
                send_msg(msg, channel)

def choices(sc, data):
    """Usage: !choices. Show current choices people are voting on."""
    if type(data)==type({}):
        if "channel" in data.keys():
            if data["channel"] and (type(data["channel"]) in string_types):
                channel = data["channel"]
                msg = u""
                attachments = []
                if not len(CHOICES):
                    msg = u"No choices currently added"
                else:
                    for index, choice in enumerate(CHOICES):
                        msg += u"{0}. {1}\n".format(index+1, choice.name)
                        response = choice.build_attachment()
                        if type(response) == type({}):
                            attachments.append(response)
                        '''if choice.url:
                            msg += choice.url + "\n"'''
                logging.info(msg)
                logging.info(attachments)
                post_attachment(msg, channel, attachments)
    
def show_poll(sc, data):
    """Usage: !show_poll. Show current rankings."""
    if type(data)==type({}):
        if "channel" in data.keys():
            if data["channel"] and (type(data["channel"]) in string_types):
                msg = u""
                if not len(CHOICES):
                    msg = u"No poll to show"
                else:
                    tmp = copy.deepcopy(CHOICES)
                    tmp = sorted(tmp, key=get_key, reverse=True)
                    for index, item in enumerate(tmp):
                        msg += u"{0}. {1} with {2} votes\n".format(index+1, item.name, item.votes)
                logging.info(msg)
                send_msg(msg, data["channel"])
    
def attendees(sc, data):
    """Usage: !attendees. Shows a list of people currently RSVP'ed."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            if len(ATTENDEES):
                msg = u"Attending: "
                if data["channel"] and (type(data["channel"]) in string_types):
                    msg += ", ".join([get_name(sc, user) for user in ATTENDEES])
            else:
                msg = u"No one currently attending"
            logging.info(msg)
            send_msg(msg, channel)

def help(sc, data):
    """Usage: !help. Displays this message."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            msg = "```{0:15}{1}\n".format("!help", help.__doc__)
            temp_cmds = COMMANDS
            temp_cmds = sorted(temp_cmds)
            for cmd in temp_cmds:
                if cmd!="!help":
                    msg += "{0:15}{1}\n".format(cmd, COMMANDS[cmd].__doc__)
            msg.expandtabs
            msg += "```"
            logging.info(msg)
            send_msg(msg, channel)

def when(sc, data):
    """Usage: !when. Displays when the next food day is"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            d = datetime.date.today()
            days_ahead = 4 - d.weekday()
            if days_ahead <0:
                days_ahead +=7
            d = d + datetime.timedelta(days_ahead)
            if (d == datetime.date.today()):
                msg = "Today is food day!!1one!"
            else:
                msg = d.strftime("Next food day is on %A, %B %d, %Y.")
            logging.info(msg)
            send_msg(msg, channel)

def recommend(sc, data):
    """Usage: !recommend <category>. Get top yelp recommendations for the given term"""
    if type(data)==type({}):
        if "channel" in data.keys() and "data" in data.keys():
            if data["data"].strip() and data["channel"].strip():
                channel = data["channel"]
                term = data["data"]
                if len(term)<40:
                    attachments = []
                    recommendations = build_fr_term(term, range(3))
                    if type(recommendations)==type([]):
                        for recommendation in recommendations:
                            try:
                                attachments.append(recommendation.build_attachment())
                            except:
                                pass
                        msg = u"Top {0} recommendations for {1} near Poly.".format(len(attachments), term)
                        logging.info(attachments)
                        post_attachment(msg, channel, attachments)
                    else:
                        msg = u"No recommendations available."
                        logging.info(msg)
                        send_msg(msg, channel)
                else:
                    msg = u"Recommendation query too long"
                    send_msg(msg, channel)

def source(sc, data):
    """Usage: !source. Uploads a snippet with the bot's source code"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            filename = __file__
            with open(filename, "rb") as r:
                response = upload_file(channel, r, filename, filename)
                logging.info(response)

config = {}
with open("config.json", "r") as r:
    config = json.load(r)

token = config["token"]
yck = config["yck"]
ycs = config["ycs"]
ytok = config["ytok"]
yts = config["yts"]

cnl = ""
ATTENDEES = []
VOTES = {}
CHOICES = []
USERS = {}
USERNAME = "PwnBot"
LOCATION = "6 Metrotech Ctr, Brooklyn, NY"
COMMANDS = {"!vote": globals()["vote"], "!rsvp": globals()["rsvp"], "!attendees": globals()["attendees"], "!dersvp": globals()["dersvp"],
        "!choices": globals()["choices"], "!help": globals()["help"], "!show_poll": globals()["show_poll"], "!when": globals()["when"],
        "!recommend": globals()["recommend"], "!source": globals()["source"], "!gif": globals()["gif"], "!ctfmode": globals()["ctfmode"],
        "!bin": globals()["bin"], "!delete": globals()["delete"], "!file_list": globals()["file_list"], "!request": globals()["request"], 
        "!rename": globals()["rename"], "!analyze": globals()["analyze"], "!coinflip": globals()["coinflip"], "!applause": globals()["applause"], "!clearfiles": globals()["clearfiles"]}
string_types = [type(u""), type("")]
sc = SlackClient(token)
yelp = YelpAPI(yck, ycs, ytok, yts)
ctfmode = False
req_key = False
current_dir = "./"
logging.basicConfig(filename = "loggedoutput.log", level = logging.DEBUG)

if sc.rtm_connect():
    cnl = sc.server.channels.find("testchan")
    while True:
        #try:
        read = {}
        try:
            read = sc.rtm_read()
        except:
            if sc.rtm_connect():
                read = sc.rtm_read()
        for d in read:
            if ("type" in d.keys()):
                if d["type"]=="message" and d['channel']==cnl.id and ("subtype" not in d.keys()):    #for if solid is being a cunt: and d["user"] != "U02JZ4EF3":
                    msg = d["text"]
                    cmd, options = split_msg(msg)
                    user = d["user"]
                    logging.info(d["type"] + ", " + d["user"] + ", " + d["channel"] + ", " + d["text"])
                    args = {"data": options, "user": user, "channel": cnl.id}
                    if cmd in COMMANDS.keys():
                        try:
                            if args["data"] != "":
                                args["data"].decode('ascii')
                            logging.info("Calling {0}".format(cmd) + "with arguments " + str(args))
                            COMMANDS[cmd](sc, args)
                        except UnicodeDecodeError:
                            logging.info("invalid options")
                            send_msg("WRONG", args["channel"])
                if "file" in d and d["type"] == "file_shared": 
                    if "preview" not in d["file"].keys() or d["file"]["preview"] != "#THIS STRING IS SO THAT PWNBOT DOES NOT DOWNLOAD ITSELF DO NOT DELETE":# and d["user"] != "U02JZ4EF3":
                        logging.info(str(d["type"]) + ", " + str(d["file"]))
                        privurl = d["file"]["url_private"]
                        args = {"data": "<"+privurl+">", "user": "download", "channel": cnl.id, "filename": d["file"]["name"]}
                        req_key = True
                        bin(sc, args)
        time.sleep(0.3)
        #except:
         #   logging.warning("Major bork pls assist")
