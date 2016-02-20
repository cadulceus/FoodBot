#-*- coding: utf-8 -*-
#ROPgadget written by salwan, libc fingerprinter, checksec.sh slimm609, libc database niklasb, file (bash file)
#85a471229b705a3cd3db22499a0bc8acc8d8b4fd
import time, json, copy, datetime, requests, re, wget, hashlib, binascii, os
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
    with open("filelist.txt", "r") as f:
        rawlist = (f.read()).split()
        x = 0
        filelist = []
        while x < len(rawlist):
            if x%2==0:
                filelist.append(rawlist[x])
            x+=1
        return filelist

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

def send_msg(txt, cnl):
    sc.api_call("chat.postMessage", channel=cnl, username=USERNAME, text=txt)

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
    print response.content

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
    print name
    print url
    print rating
    print img_url
    print categories
    print address
    print phone
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
    print pricing_values
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

#to add: auto extraction/unzipping & recursive directory exploration, bulk analysis when ctfmode, stat, all the tools at the top
def analyze(sc, data):
    """usage: !analyze <filename>. Gives useful data about a binary file"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            filename = data["data"]
            if filename in get_filelist():
                outstring = ""
                file_out = check_output(["file", filename])
                outstring += file_out + "\n---------------------------\n"
                filetype = file_out[len(filename)+2:file_out.find(",")]
                stat_out = check_output(["stat", filename])
                outstring += stat_out[:stat_out.find("\nAccess: ")] + "\n---------------------------\n"
                binwalk_out = check_output(["binwalk", filename])
                outstring += binwalk_out + "\n"

                send_msg(outstring, channel)
            else:
                send_msg("File does not exist", channel)
        
            
def rename(sc, data):
    """usage: !rename <filename> <new name>. Renames a file"""
    if type(data)==type({}):
        channel = data["channel"]
        filelist = get_filelist()
        rawlist = open("filelist.txt", "r").read().split()
        params = data["data"].split()
        if params[0] in filelist and len(params)==2:
            os.rename(params[0], params[1])
            f = open("filelist.txt", "w")
            for raw in rawlist:
                if raw == params[0]:
                    f.write(params[1] + "\n")
                else:
                    f.write(raw + "\n")
            send_msg("File sucessfully renamed to " + params[1], channel)
        elif len(params)==2:
            send_msg("Invalid parameters")
        else:
            send_msg("File does not exist")

#to add: pull down all challenges on a CTF page, add trello integration
def bin(sc, data):
    """usage: !bin <download link>. For giving files to pwnbot when ctfmode is off. alternative usage: !bin grabnext. creates and download a public link for the next uploaded file."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            url = (data["data"])[1:-1]
            print url
            if data["data"] == "grabnext":
                global grabnext
                grabnext = True
                send_msg("Downloading next uploaded file", channel)
            else:
                try:
                    r = wget.download(url)
                    md5checksum = hashlib.md5(open(r).read()).hexdigest()
                    rawlist = (open("filelist.txt", "r").read()).split()
                    if md5checksum in rawlist:
                        raise FileExists()
                    f = open("filelist.txt", "a")
                    f.write(r + "\n")
                    f.write(md5checksum + "\n")
                    f.close()
                    send_msg("File "+ r + "  downloaded successfully", channel)
                    print "File downloaded successfully"
                except FileExists:
                    print "File already exists"
                    existing = rawlist[rawlist.index(md5checksum)-1]
                    send_msg("File already exists as " + existing, channel)
                    os.remove(r)
                except:
                    print "couldnt find a downloadable file"
                    send_msg("Couldn't find a downloadable file", channel)

def file_list(sc, data):
    """usage: !filelist. Lists files."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            filelist = get_filelist()
            output = ""
            for item in filelist:
                output += item + "\n"
            send_msg(output, channel)

def request(sc, data):
    """usage: !request <filename>. Pwnbot uploads the requested file"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            filelist = get_filelist()
            rqfile = data["data"]
            if rqfile in filelist:
                with open(rqfile, "rb") as f:
                    upload_file(channel, f, rqfile, rqfile)
                    print "File uploaded"
            else:
                print "File not found"
                send_msg("Could not find file", channel)

def delete(sc, data):
    """usage: !delete <filename>. For deleting files that slackbot has downloaded"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            f = open("filelist.txt", "r")
            slist = (f.read()).split()
            f.close()
            if data["data"] in slist:
                f = open("filelist.txt", "w")
                md5flag = False
                for fil in slist:
                    if fil != data["data"] and md5flag == False:
                        f.write(fil + "\n")
                    elif not md5flag:
                        md5flag = True
                    else:
                        md5flag = False
                os.remove(data["data"])
            send_msg("File " + data["data"] + " deleted", channel)

#to add: folder organization by CTF
def ctfmode(sc, data):
    """ toggle ctfmode which allows creation of public files to pull down files without requiring links"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            global ctfmode
            ctfmode = not ctfmode
            send_msg("ctfmode is set to " + str(ctfmode), channel)
         
def gif(sc, data):
    """imgur image search"""
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
            print query
            if len(imgurls) == 0:
                print "no results"
                send_msg("No results", channel)
            elif len(imgurls) <= 10 or query == "":
                print "not enough images, or catchall query"
                send_msg(imgurls[randint(0, len(imgurls)-1)], channel)
            else:
                send_msg(imgurls[randint(0, 10)], channel)


def rsvp(sc, data):
    """indicate that you will be attending the event."""
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
                print msg
                send_msg(msg, channel)

def dersvp(sc, data):
    """remove name from list of attendees."""
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
                print msg
                send_msg(msg, channel)

def vote(sc, data):
    """[choice] cast your vote for choice. Choice can be an existing option's number as shown in !choices, choice name, or a new option."""
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
                    print msg
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
                print msg
                send_msg(msg, channel)

def choices(sc, data):
    """show current choices people are voting on."""
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
                print msg
                print attachments
                post_attachment(msg, channel, attachments)
    
def show_poll(sc, data):
    """show current rankings."""
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
                print msg
                send_msg(msg, data["channel"])
    
def attendees(sc, data):
    """shows a list of people currently RSVP'ed."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            if len(ATTENDEES):
                msg = u"Attending: "
                if data["channel"] and (type(data["channel"]) in string_types):
                    msg += ", ".join([get_name(sc, user) for user in ATTENDEES])
            else:
                msg = u"No one currently attending"
            print msg
            send_msg(msg, channel)

def help(sc, data):
    """displays this message."""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            msg = "{0:15}{1}\n".format("!help", help.__doc__)
            temp_cmds = COMMANDS
            temp_cmds = sorted(temp_cmds)
            for cmd in temp_cmds:
                if cmd!="!help":
                    msg += "{0:15}{1}\n".format(cmd, COMMANDS[cmd].__doc__)
            msg.expandtabs
            print msg
            send_msg(msg, channel)

def when(sc, data):
    """displays when the next food day is"""
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
            print msg
            send_msg(msg, channel)

def recommend(sc, data):
    """[term] get top yelp recommendations for the given term"""
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
                        print attachments
                        post_attachment(msg, channel, attachments)
                    else:
                        msg = u"No recommendations available."
                        print msg
                        send_msg(msg, channel)
                else:
                    msg = u"Recommendation query too long"
                    send_msg(msg, channel)

def source(sc, data):
    """uploads a snippet with the bot's source code"""
    if type(data)==type({}):
        if "channel" in data.keys():
            channel = data["channel"]
            filename = __file__
            with open(filename, "rb") as r:
                response = upload_file(channel, r, filename, filename)
                print response

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
        "!recommend": globals()["recommend"], "!source": globals()["source"], "!gif": globals()["gif"], "!ctfmode": globals()["ctfmode"], "!bin": globals()["bin"], "!delete": globals()["delete"], "!file_list": globals()["file_list"], "!request": globals()["request"], "!rename": globals()["rename"], "!analyze": globals()["analyze"]}
string_types = [type(u""), type("")]
sc = SlackClient(token)
yelp = YelpAPI(yck, ycs, ytok, yts)
ctfmode = False
grabnext = False
if sc.rtm_connect():
    cnl = sc.server.channels.find("food-day")
    while True:
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
                    args = {"data": options, "user": user, "channel": cnl.id}
                    if cmd in COMMANDS.keys():
                        try:
                            if args["data"] != "":
                                args["data"].decode('ascii')
                            print "Calling {0}".format(cmd), "with arguments ", args
                            COMMANDS[cmd](sc, args)
                        except UnicodeDecodeError:
                            print "invalid options"
                            send_msg("WRONG", args["channel"])
                if "file" in d and (ctfmode == True or grabnext == True):# and d["user"] != "U02JZ4EF3":
                    grabnext = False
                    public_creator = d['file']['permalink_public']
                    print "File Found. public link creator: {0}".format(public_creator)
                    #sc.api_call("files.list"
                    r = requests.get(public_creator)
                    loc = (r.content).find('"file_header generic_header" href="')
                    if loc == "":
                        loc = (r.content).find('img src="')
                    dllink = (r.content)[35+loc:200+loc]
                    dllink = dllink[:dllink.find('">')]
                    print "public download link: ", dllink
                    args = {"data": "<"+dllink+">", "user": "thisstringneedstobehere", "channel": cnl.id}
                    bin(sc, args)
        time.sleep(0.5)
