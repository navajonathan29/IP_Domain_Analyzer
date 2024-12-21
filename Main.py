import pandas as pd
import plotly.express as px
import main_function
import streamlit as st
import requests
import numpy as np

# API handling
api_key = main_function.read_from_file("api_key1.json")

#--------------------API INTEGRATION--------------------------

# AbuseIPDB API key
abuseIPDB_key = api_key["abuseipdb_key"]
url = 'https://api.abuseipdb.com/api/v2/check'

# function fetches data from AbuseIPDB API
def fetch_abuseipdb_data(ip):
    headers = {
        'Key': abuseIPDB_key,
        'Accept': 'application/json'
    }
    response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        st.error("Failed to fetch data from AbuseIPDB.")
        st.write("Response status code:", response.status_code)
        st.write("Response Text:", response.text)
        return None

# Security Trails api implementation
securityTrails_key = api_key["securityTrails_key"]
# this function accepts domain name and returns json of dns history.
def fetch_recent_ips(domain,limit):

    sectrails_url = f"https://api.securitytrails.com/v1/history/{domain}//dns/a"

    headers = {
        'Content-Type': 'application/json',
        'APIKEY': securityTrails_key
    }

    response = requests.get(sectrails_url,headers=headers)

    if response.status_code == 200:
        data = response.json()

        # Extract IPs from the 'records' field
        ip_addresses = []
        records = data.get("records",[])

        # set a limit for the max amount of IPs to be returned
        if limit is None:
            limit = 5

        for record in records:
            values = record.get("values",[])
            for value in values:
                ip = value.get("ip")
                if ip and ip not in ip_addresses: # Ensure IP exists and is unique
                    ip_addresses.append(ip)
                    if len(ip_addresses) == limit:
                        return ip_addresses
    else:
        st.error("Failed to fetch data from SecurityTrails.")
        st.write("Response status code:", response.status_code)
        st.write("Response Text:",response.text)
        return None

# This function gets the lat/long of a given ip
def fetch_geolocator(ip):
    response = requests.get(f'https://ipwho.is/{ip}')

    data = response.json()
    return data


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~ MAIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Image header
# (Source: https://rita-malaquias.tumblr.com/post/624628008985165824/pixel-dailies-tweet-here-theme-was-hacker )
st.image("hacking-pixel-art.png",
         width = 500,
         caption="Photo by Rita Malaquias on Tumblr")

# Title
st.title("IP Analyzer/DNS Lookup")
option_sidebar = st.sidebar.selectbox("Choose option",
                                      ("DNS Reputation","IP Analyzer"))

#Sidebar features
st.sidebar.subheader("Visualize IP Reputation Data")
uploaded_file = st.sidebar.file_uploader("Enter IP CSV",type=["csv"])

#Reading files
df1 = pd.read_csv("phish_score2.csv")
df2 = pd.read_csv("reports_chart.csv")

# START OF IP ANALYZER OPTION FEATURES
if option_sidebar == "IP Analyzer":
    # insert here ip that you would want to check
    ip_to_check = st.text_input("Enter an IP address to check:", placeholder="Ex: 209.85.128.181")
    st.caption("You can view a list of malicious IP Addresses at https://github.com/romainmarcoux/malicious-ip/blob/main/full-40k.txt.")

    if 'clicked' not in st.session_state:
        st.session_state.clicked = False

    def click_button():
        st.session_state.clicked = True

    submit_button = st.button("View report", on_click=click_button)
    full_report = st.checkbox("I want to view additional data")

    if st.session_state.clicked:
        if ip_to_check:
            #this line fetches all the relevant data
            abuse_data = fetch_abuseipdb_data(ip_to_check)

            # Extract relevant fields from response
            report_data = abuse_data.get("data", {})
            abuse_score = report_data.get("abuseConfidenceScore",0)
            country_code = abuse_data.get("countryCode","Unknown")
            countryName = abuse_data.get("countryName","Unknown")
            total_reports = abuse_data.get("totalReports", 0)
            last_reported_at = abuse_data.get("lastReportedAt", "N/A")
            domainName = abuse_data.get("domain","N/A")

            # HERE IS WHERE THE STREAMLIT FEATURES START!!!!!!!!!

            # abuse score rating
            if abuse_score >= 20:
                st.error(f"High malicious confidence Score of ({abuse_score}%) for this IP address!")
            elif abuse_score >= 10:
                st.warning(f"Suspiciously High malicious confidence Score of ({abuse_score}%) for this IP address.")
            else:
                st.success(f"This IP has a low abuse score ({abuse_score}%).")

            st.divider()
            st.subheader(f"AbuseIPDB Report for IP: {ip_to_check}")
            # Display relevant fields from the data
            st.write("Abuse Confidence Score:", report_data.get("abuseConfidenceScore"))
            st.write("Country:", report_data.get("countryCode"))
            st.write("Total Reports:", report_data.get("totalReports"))
            st.write("Last Reported At:",report_data.get("lastReportedAt"))
            st.divider()

            # TABS
        if full_report:
            map_region, descriptive_table, bar_chart, line_chart = st.tabs(["Map",
                                                                        "Interactive Table",
                                                                        "Bar Graph",
                                                                        "Line Chart"])
            with map_region:
                st.subheader("IP Geolocation")
                try:
                    geolocator = fetch_geolocator(ip_to_check)
                    latitude = geolocator["latitude"]
                    longitude = geolocator["longitude"]
                    color = st.color_picker("Choose a color", "#00f900")

                    map_df = pd.DataFrame(
                        {
                            "col1": latitude,
                            "col2": longitude,
                            "size": 300,
                            "color": np.random.rand(1000,4).tolist(),
                        }
                    )
                    st.map(map_df, latitude="col1",longitude="col2",size="size",color=color)
                    st.caption(f"This map represents the latitude and longitude of IP Address you entered: {ip_to_check}")
                except Exception as e:
                    st.error(f"Could not geolocate: {ip_to_check}.")

            with descriptive_table:
                st.subheader("Visual CSV Data")
                if uploaded_file is None:
                    # Read the CSV file into a pandas Dataframe
                    df = pd.read_csv("IP csv.csv")
                    st.text(
                        "This data sample is taken from projecthoneypot.org. Last updated November 27th.")
                    # Display data frame
                    st.subheader("Top 25 malicious IP addresses")
                    st.dataframe(df)
                else:
                    # if user wants to upload their own csv, this will display their csv
                    df = pd.read_csv(uploaded_file)
                    st.write("Preview of the uploaded CSV:")
                    st.dataframe(df)

            with bar_chart:
                st.subheader("Bar chart")
                st.text(
                    "This curated data shows a sample look at other recent IPs and their given phishing ")
                st.text("scores each day from PhishStats.info from the date 10/30/2024. This data is meant ")
                st.text("to give comparative information.")
                st.warning(
                    "Warning: All URLs with its associated IP most likely contain phishing information that should not be visited. This information is purely for educational purposes.")
                fig1 = px.bar(df1, x=df1.Date, y="Score", title="Overall Phishing", hover_data=['URL', 'IP'], color="IP",
                                  height=400)
                fig1.update_traces(marker_color='#748CEF')
                st.plotly_chart(fig1)

            with line_chart:
                st.subheader("Line Chart")
                st.text(
                    "This curated data shows recent reported IP addresses from AbuseIPDB.com. This data ")
                st.text("is meant to give comparative information.")
                st.warning(
                    "Warning: Reports from these IP addresses were recently reported with abusive activity that should not be visited. This information is purely for educational purposes.")
                fig2 = px.line(df2, x=df2.Date, y="Reports", title="Line Chart",
                                   hover_data=['IP', 'Date', 'Reports', 'Domain'], color="IP", height=400)
                st.plotly_chart(fig2)

# END OF IP ANALYZER OPTION FEATURES

# START OF DNS LOOKUP OPTION FEATURES
if option_sidebar == "DNS Reputation":
    domain = st.text_input("Enter a Domain name to check:", placeholder="Ex: 123movies.faith")
    st.caption("(You can view a list of domains at https://github.com/mitchellkrogza/Phishing.Database/blob/master/phishing-domains-ACTIVE.txt )")

    # layout for checkbox, slider, and submit button in one row
    col1, col2 = st.columns([2,2]) # adjust column widths as needed.

    with col1:
        submit_button = st.button("View report")
        full_report = st.checkbox("I want to view additional data")
    with col2:
        limit = st.slider("How many recent IPs would you like to check:",min_value=1, max_value=5, value=3)

    highest_score = 0
    high_score_ip = 0

    if submit_button:
        if domain:
            recent_ips = fetch_recent_ips(domain,limit)
            if recent_ips:
                st.divider()
                st.subheader(f"Recent IP Addresses for {domain}:")

                counter=0
                for ip in recent_ips:
                    st.write(f"Checking reputation for IP: {ip}.")

                    # get abuse confidence score for each ip
                    reputation_data = fetch_abuseipdb_data(ip)
                    report_data = reputation_data.get("data",{})
                    abuse_score = report_data.get("abuseConfidenceScore",0)

                    # save the highest malicious ip
                    if abuse_score > highest_score:
                        highest_score = abuse_score
                        high_score_ip = ip

                    # Let the user know there if failed to retrieve data
                    if reputation_data is None:
                        st.write(f"Failed to retrieve reputation data for {ip}.")
                    else:
                        counter+=1
                if counter < limit:
                    st.warning(f"Only {counter} IP addresses found.")
                # after loop is done iterating, grab the highest score and let the user
                # know that this domain has or hasn't had malicious history
                if highest_score >= 20:
                    st.error(f"{domain} has high malicious history at {high_score_ip}.")
                elif highest_score >= 10:
                    st.warning(f"{domain} has suspiciously high malicious history at {high_score_ip}.")
                else:
                    st.success(f"{domain} is safe!")
            else:
                st.write(f"No IP addresses found for {domain}.")
        else:
            st.error("Could not geolocate this domain")

        if full_report:
            map_region, descriptive_table, bar_chart, line_chart = st.tabs(["Map",
                                                                            "Interactive Table",
                                                                            "Bar Graph",
                                                                            "Line Chart"])
            # TOOOOO DOOOOOO / COPY THE TABS FROM IP ANALYZER AND IMPLEMENT
            # THEM INTO DNS LOOKUP AND SHOW THE LAT LONG OF THE HIGHEST SCORE IP
            # TABS
            with map_region:
                st.subheader("IP Geolocation")
                if high_score_ip is not 0:
                    try:
                        geolocator = fetch_geolocator(high_score_ip)
                        latitude = geolocator["latitude"]
                        longitude = geolocator["longitude"]

                        map_df = pd.DataFrame(
                            {
                                "col1": latitude,
                                "col2": longitude,
                                "size": 300,
                                "color": np.random.rand(1000, 4).tolist(),
                            }
                        )
                        st.map(map_df, latitude="col1", longitude="col2", size="size", color="color")
                        st.caption(f"This map represents the latitude and longitude of the IP address with the highest"
                           f" malicious history associated with {domain} at  : {high_score_ip}")
                    except Exception as e:
                        st.error(f"Could not geolocate: {high_score_ip}")
                else:
                    st.write("Enter valid Domain Name to geolocate.")

            with descriptive_table:
                st.subheader("Visual CSV Data")
                if uploaded_file is None:
                    # Read the CSV file into a pandas Dataframe
                    df = pd.read_csv("IP csv.csv")

                    st.text(
                        "This data sample is taken from projecthoneypot.org. Last updated November 27th.")

                    # Display data frame
                    st.subheader("Top 25 malicious IP addresses")
                    st.dataframe(df)
                else:
                    # if user wants to upload their own csv, this will display their csv
                    df = pd.read_csv(uploaded_file)
                    st.write("Preview of the uploaded CSV:")
                    st.dataframe(df)
            with bar_chart:
                st.subheader("Bar Chart")
                st.text(
                    "This curated data shows a sample look at other recent IPs and their given phishing ")
                st.text("scores each day from PhishStats.info from the date 10/30/2024. This data is meant ")
                st.text("to give comparative information.")
                st.warning(
                    "Warning: All URLs with its associated IP most likely contain phishing information that should not be visited. This information is purely for educational purposes.")
                fig1 = px.bar(df1, x=df1.Date, y="Score", title="Overall Phishing", hover_data=['URL', 'IP'], color="IP",
                              height=400)
                fig1.update_traces(marker_color='#748CEF')
                st.plotly_chart(fig1)
            with line_chart:
                st.subheader("Line Chart")
                st.text(
                    "This curated data shows recent reported IP addresses from AbuseIPDB.com. This data ")
                st.text("is meant to give comparative information.")
                st.warning(
                    "Warning: Reports from these IP addresses were recently reported with abusive activity that should not be visited. This information is purely for educational purposes.")
                fig2 = px.line(df2, x=df2.Date, y="Reports", title="Line Chart",
                               hover_data=['IP', 'Date', 'Reports', 'Domain'], color="IP", height=400)
                st.plotly_chart(fig2)