import threading
import pandas as pd
import os
import streamlit as st
import configparser
import csv
import time
import asyncio
from telethon.sync import TelegramClient
from telethon.tl.functions.messages import GetDialogsRequest
from telethon.tl.types import InputPeerEmpty
from telethon.tl.types import InputPeerUser
from telethon.errors import FloodWaitError, SessionPasswordNeededError


def banner():
    st.title("Setup")


def config_setup():
    banner()
    st.write("### API Configuration Setup")
    cpass = configparser.RawConfigParser()
    cpass.add_section("cred")
    xid = st.text_input("Enter API ID:")
    cpass.set("cred", "id", xid)
    xhash = st.text_input("Enter Hash ID:")
    cpass.set("cred", "hash", xhash)
    xphone = st.text_input("Enter Phone Number:")
    cpass.set("cred", "phone", xphone)
    if st.button("Save Configuration"):
        with open("config.data", "w") as setup:
            cpass.write(setup)
        st.success("Configuration data saved successfully!")


def load_config():
    cpass = configparser.RawConfigParser()
    cpass.read("config.data")
    return {
        "api_id": cpass.get("cred", "id"),
        "api_hash": cpass.get("cred", "hash"),
        "phone": cpass.get("cred", "phone"),
    }


async def async_scrape_members(config):
    client = TelegramClient(config["phone"], int(config["api_id"]), config["api_hash"])
    try:
        await client.connect()

        if not await client.is_user_authorized():
            st.warning(
                "You are not authorized. Please check your phone for the authentication code."
            )
            try:
                await client.send_code_request(config["phone"])
                st.success("Authentication code sent successfully.")
            except FloodWaitError as e:
                wait_seconds = e.seconds
                st.error(
                    f"You must wait {wait_seconds} seconds before trying again due to Telegram's rate limiting."
                )
            except Exception as e:
                st.error(f"Failed to request authentication code: {str(e)}")

            code = st.text_input("Enter the code sent to your phone:")
            if code:
                try:
                    await client.sign_in(config["phone"], code)
                    if not await client.is_user_authorized():
                        st.error("Failed to sign in. Please try again.")
                        return
                    else:
                        st.success("Successfully signed in!")
                except SessionPasswordNeededError:
                    password = st.text_input(
                        "Two-step verification is enabled. Enter your password:"
                    )
                    try:
                        await client.sign_in(password=password)
                    except Exception as e:
                        st.error(f"Failed to sign in: {str(e)}")
                        return
                except Exception as e:
                    st.error(f"Failed to sign in: {str(e)}")
                    return
        if await client.is_user_authorized():
            st.success("Successfully connected to Telegram client.")
            if "groups" not in st.session_state or st.button("Reload Groups"):
                chats = []
                last_date = None
                chunk_size = 200
                groups = []

                result = await client(
                    GetDialogsRequest(
                        offset_date=last_date,
                        offset_id=0,
                        offset_peer=InputPeerEmpty(),
                        limit=chunk_size,
                        hash=0,
                    )
                )
                chats.extend(result.chats)

                for chat in chats:
                    if getattr(chat, "megagroup", False):
                        groups.append(chat)

                st.session_state["groups"] = groups
                st.session_state["selected_group_title"] = None  # Reset on reload

            if not st.session_state["groups"]:
                st.error("No groups found.")
                return

            group_titles = [f"{group.title}" for group in st.session_state["groups"]]
            selected_group_title = st.selectbox(
                "Choose a group to scrape members from:",
                group_titles,
                index=0,
                key="group_selector",
            )

            if st.session_state.get("selected_group_title") != selected_group_title:
                st.session_state["selected_group_title"] = selected_group_title

            if selected_group_title:
                selected_index = group_titles.index(selected_group_title)
                target_group = st.session_state["groups"][selected_index]

                csv_file_name = st.text_input(
                    "Enter a name for the CSV file:", value="members.csv"
                )

                if st.button("Fetch Members"):
                    # Fetch members
                    st.warning("Fetching members...")
                    all_participants = await client.get_participants(
                        target_group, aggressive=True
                    )

                    # Save to CSV
                    st.warning(f"Saving members to {csv_file_name}...")
                    with open(csv_file_name, "w", encoding="UTF-8") as f:
                        writer = csv.writer(f, delimiter=",", lineterminator="\n")
                        writer.writerow(
                            [
                                "username",
                                "user_id",
                                "access hash",
                                "name",
                                "group",
                                "group id",
                            ]
                        )
                        for user in all_participants:
                            username = user.username if user.username else ""
                            first_name = user.first_name if user.first_name else ""
                            last_name = user.last_name if user.last_name else ""
                            name = (first_name + " " + last_name).strip()
                            writer.writerow(
                                [
                                    username,
                                    user.id,
                                    user.access_hash,
                                    name,
                                    target_group.title,
                                    target_group.id,
                                ]
                            )
                        st.success(
                            f"Members have been successfully saved to '{csv_file_name}'."
                        )

        else:
            st.error("Failed to connect to Telegram client.")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        await client.disconnect()


async def async_sign_in(client, phone):
    try:
        await client.connect()
        if not await client.is_user_authorized():
            st.warning(
                "You are not authorized. Please check your phone for the authentication code."
            )
            try:
                await client.send_code_request(phone)
                st.success("Authentication code sent successfully.")
            except FloodWaitError as e:
                st.error(
                    f"You must wait {e.seconds} seconds before trying again due to Telegram's rate limiting."
                )
            except Exception as e:
                st.error(f"Failed to request authentication code: {str(e)}")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")


async def sign_in_telegram():
    config = load_config()
    client = TelegramClient(config["phone"], config["api_id"], config["api_hash"])

    if "auth_status" not in st.session_state:
        st.session_state["auth_status"] = "not_started"

    if st.session_state["auth_status"] == "not_started":
        asyncio.run(async_sign_in(client, config["phone"]))
        if client.is_connected():
            st.session_state["auth_status"] = "code_sent"

    if st.session_state["auth_status"] == "code_sent":
        code = st.text_input("Enter the code sent to your phone:")
        if code:
            try:
                await client.sign_in(config["phone"], code)
                if await client.is_user_authorized():
                    st.session_state["auth_status"] = "signed_in"
                    st.success("Successfully signed in!")
                else:
                    st.error("Failed to sign in. Please check the code and try again.")
            except SessionPasswordNeededError:
                # Handle two-step verification
                st.session_state["auth_status"] = "awaiting_2fa"
                password = st.text_input(
                    "Two-step verification is enabled. Enter your password:"
                )
                if password:
                    try:
                        await client.sign_in(password=password)
                        st.session_state["auth_status"] = "signed_in"
                        st.success("Successfully signed in!")
                    except Exception as e:
                        st.error(
                            f"Failed to sign in with two-step verification: {str(e)}"
                        )
            except Exception as e:
                st.error(f"Failed to sign in: {str(e)}")


async def send_messages_async(users, message_template, sleep_time):
    config = load_config()
    async with TelegramClient(
        config["phone"], config["api_id"], config["api_hash"]
    ) as client:
        await client.connect()
        if not client.is_user_authorized():
            raise Exception("Client not authorized. Please check your authentication.")

    sent_users = []
    for user in users:
        try:
            # ensure client is connected before sending message
            if not client.is_connected():
                await client.connect()

            user_id = int(user["user_id"])
            access_hash = int(user["access hash"])  # Corrected key name here
            receiver = InputPeerUser(user_id, access_hash)

            # Send message
            await client.send_message(receiver, message_template.format(user["name"]))
            print(f"Sent message to {user['name']}")
            sent_users.append(user)
            # Wait before sending the next message
            await asyncio.sleep(sleep_time)
        except Exception as e:
            print(f"Failed to send message to {user['name']}: {str(e)}")
            continue
    return sent_users


def run_async(users, message_template, sleep_time):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(send_messages_async(users, message_template, sleep_time))


def upload_and_send():
    st.subheader("Upload CSV and Send Messages")
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        users = df.to_dict("records")  # Convert dataframe to list of dicts

        message_template = st.text_area(
            "Enter your message:",
            value="Hello, write here the message!",
            help="Write your message that the bot will send to each user.",
        )
        sleep_time = st.number_input(
            "Seconds to wait between messages:", min_value=1, value=10
        )

        if st.button("Send Messages"):
            # Adjusting this section to handle the event loop more gracefully
            try:
                # show spinner while sending messages
                with st.spinner("Sending messages..."):
                    thread = threading.Thread(
                        target=run_async, args=(users, message_template, sleep_time)
                    )
                    thread.start()
                    thread.join()
                    # crete new dataframe with sent users
                    sent_users_df = pd.DataFrame(users)
                    sent_users_df.to_csv("sent_users.csv", index=False)
                    st.success("Sent users saved to 'sent_users.csv'.")
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
            else:
                st.success("Messages sent successfully.")


def scrape_members():
    banner()
    config = load_config()

    with st.spinner("Scraping members..."):
        asyncio.run(async_scrape_members(config))


# Modify main or appropriate functions to include the sign-in logic
def main():
    config_setup()
    sign_in_telegram()
    scrape_members()
    upload_and_send()


if __name__ == "__main__":
    main()
