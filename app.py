import json
import os
import streamlit as st
from streamlit import session_state
from dotenv import load_dotenv
import smtplib
import random
import string
import re
import datetime
import pandas as pd
from pathlib import Path
import hashlib
import google.generativeai as genai

st.set_page_config(
    page_title="Detect Illicit Content System",
    page_icon="favicon.ico",
    layout="wide",
    initial_sidebar_state="expanded",
)

session_state = st.session_state
if "user_index" not in st.session_state:
    st.session_state["user_index"] = 0

load_dotenv()

safety_settings = [
    {
        "category": "HARM_CATEGORY_DANGEROUS",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_NONE",
    },
]


def classify_image(image_path: str) -> str:
    genai.configure(api_key=os.getenv("GENAI_API_KEY"))

    # Set up the model with desired settings
    generation_config = {
        "temperature": 1,
        "top_p": 0.95,
        "top_k": 0,
        "max_output_tokens": 8192,
    }
    prompt = f"""Given the image below, classify it on the basis of age (<=14 years, >14 years) and by gender (Male, Female). Do not use any other information apart from the image. Image can be a meme, a 
    screenshot, a painting, or any other form of visual content. The image is not suitable for children under 14 years of age only if it contains explicit content or is harmful in nature. Classify it as 'Less than or equal to 14' if it is suitable for children under 14 years of age, and 'More than 14' if it is not suitable for children under 14 years of age.


    Give the response in the following format:
    Less than or equal to 14,Male
    More than 14,Male
    Less than or equal to 14,Female
    More than 14,Female
    """
    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro-latest",
        generation_config=generation_config,
        safety_settings=safety_settings,
    )

    uploaded_files = []

    def upload_if_needed(pathname: str) -> list[str]:
        """
        Helper function to upload the image file if not already uploaded.
        """
        path = Path(pathname)
        hash_id = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            existing_file = genai.get_file(name=hash_id)
            return [existing_file]
        except:
            pass
        uploaded_files.append(genai.upload_file(path=path, display_name=hash_id))
        return [uploaded_files[-1]]

    prompt_parts = [
        prompt,
    ]
    if image_path:
        prompt_parts.extend(upload_if_needed(image_path))

    # Generate the description text
    response = model.generate_content(prompt_parts)

    for uploaded_file in uploaded_files:
        genai.delete_file(name=uploaded_file.name)

    try:
        return response.text
    except Exception as e:
        return "More than 14,Male"


def classify_text(text) -> str:
    genai.configure(api_key=os.getenv("GENAI_API_KEY"))

    # Set up the model with desired settings
    generation_config = {
        "temperature": 1,
        "top_p": 0.95,
        "top_k": 0,
        "max_output_tokens": 8192,
    }
    prompt = f"""Given the text/comment below, classify it on the basis of age (<=14 years, >14 years) and by gender (Male, Female). Do not use any other information apart from the text. A text can be a comment, a review, a message, or any other form of written communication. The text is not suitable for children under 14 years of age only if it contains explicit content or is harmful in nature. Classify it as 'Less than or equal to 14' if it is suitable for children under 14 years of age, and 'More than 14' if it is not suitable for children under 14 years of age. 
        Text: {text}

        Give the response in the following format:
        Less than or equal to 14,Male
        More than 14,Male
        Less than or equal to 14,Female
        More than 14,Female
        """
    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro-latest",
        generation_config=generation_config,
        safety_settings=safety_settings,
    )
    prompt_parts = [
        prompt,
    ]
    response = model.generate_content(prompt_parts)
    try:
        return response.text
    except Exception as e:
        return "More than 14,Male"


def user_exists(email, json_file_path):
    # Function to check if user with the given email exists
    with open(json_file_path, "r") as file:
        users = json.load(file)
        for user in users["users"]:
            if user["email"] == email:
                return True
    return False


def send_verification_code(email, code):
    SENDER_MAIL_ID = os.getenv("SENDER_MAIL_ID")
    APP_PASSWORD = os.getenv("APP_PASSWORD")
    RECEIVER = email
    server = smtplib.SMTP_SSL("smtp.googlemail.com", 465)
    server.login(SENDER_MAIL_ID, APP_PASSWORD)
    message = f"Subject: Your Verification Code\n\nYour verification code is: {code}"
    server.sendmail(SENDER_MAIL_ID, RECEIVER, message)
    server.quit()
    st.success("Email sent successfully!")
    return True


def generate_verification_code(length=6):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def signup(json_file_path="data.json"):
    st.title("Student Signup Page")
    with st.form("signup_form"):
        st.write("Fill in the details below to create an account:")
        name = st.text_input("Name:")
        email = st.text_input("Email:")
        age = st.number_input("Age:", min_value=0, max_value=120)
        sex = st.radio("Sex:", ("Male", "Female", "Other"))
        password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")
        if (
            session_state.get("verification_code") is None
            or session_state.get("verification_time") is None
            or datetime.datetime.now() - session_state.get("verification_time")
            > datetime.timedelta(minutes=5)
        ):
            verification_code = generate_verification_code()
            session_state["verification_code"] = verification_code
            session_state["verification_time"] = datetime.datetime.now()
        if st.form_submit_button("Signup"):
            if not name:
                st.error("Name field cannot be empty.")
            elif not email:
                st.error("Email field cannot be empty.")
            elif not re.match(r"^[\w\.-]+@[\w\.-]+$", email):
                st.error("Invalid email format. Please enter a valid email address.")
            elif user_exists(email, json_file_path):
                st.error(
                    "User with this email already exists. Please choose a different email."
                )
            elif not age:
                st.error("Age field cannot be empty.")
            elif not password or len(password) < 6:  # Minimum password length of 6
                st.error("Password must be at least 6 characters long.")
            elif password != confirm_password:
                st.error("Passwords do not match. Please try again.")
            else:
                verification_code = session_state["verification_code"]
                send_verification_code(email, verification_code)
                entered_code = st.text_input(
                    "Enter the verification code sent to your email:"
                )
                if entered_code == verification_code:
                    user = create_account(
                        name, email, age, sex, password, json_file_path
                    )
                    session_state["logged_in"] = True
                    session_state["user_info"] = user
                    st.success("Signup successful. You are now logged in!")
                elif len(entered_code) == 6 and entered_code != verification_code:
                    st.error("Incorrect verification code. Please try again.")


def check_login(username, password, json_file_path="data.json"):
    try:
        with open(json_file_path, "r") as json_file:
            data = json.load(json_file)

        for user in data["users"]:
            if user["email"] == username and user["password"] == password:
                session_state["logged_in"] = True
                session_state["user_info"] = user
                st.success("Login successful!")
                return user
        return None
    except Exception as e:
        st.error(f"Error checking login: {e}")
        return None


def initialize_database(json_file_path="data.json"):
    try:
        if not os.path.exists(json_file_path):
            data = {"users": []}
            with open(json_file_path, "w") as json_file:
                json.dump(data, json_file)
    except Exception as e:
        print(f"Error initializing database: {e}")


def create_account(name, email, age, sex, password, json_file_path="data.json"):
    try:
        if not os.path.exists(json_file_path) or os.stat(json_file_path).st_size == 0:
            data = {"users": []}
        else:
            with open(json_file_path, "r") as json_file:
                data = json.load(json_file)

        # Append new user data to the JSON structure
        email = email.lower()
        password = hashlib.md5(password.encode()).hexdigest()
        user_info = {
            "name": name,
            "email": email,
            "age": age,
            "sex": sex,
            "password": password,
            "report": None,
            "questions": None,
        }

        data["users"].append(user_info)

        with open(json_file_path, "w") as json_file:
            json.dump(data, json_file, indent=4)
        return user_info
    except json.JSONDecodeError as e:
        st.error(f"Error decoding JSON: {e}")
        return None
    except Exception as e:
        st.error(f"Error creating account: {e}")
        return None


def login(json_file_path="data.json"):
    st.title("Login Page")
    username = st.text_input("Email:")
    password = st.text_input("Password:", type="password")
    username = username.lower()
    password = hashlib.md5(password.encode()).hexdigest()

    login_button = st.button("Login")

    if login_button:
        user = check_login(username, password, json_file_path)
        if user is not None:
            session_state["logged_in"] = True
            session_state["user_info"] = user
        else:
            st.error("Invalid credentials. Please try again.")


def get_user_info(email, json_file_path="data.json"):
    try:
        with open(json_file_path, "r") as json_file:
            data = json.load(json_file)
            for user in data["users"]:
                if user["email"] == email:
                    return user
        return None
    except Exception as e:
        st.error(f"Error getting user information: {e}")
        return None


def render_dashboard(user_info):
    try:
        st.title(f"Welcome to the Dashboard, {user_info['name']}!")
        st.subheader("Student Information")
        st.write(f"Name: {user_info['name']}")
        st.write(f"Sex: {user_info['sex']}")
        st.write(f"Age: {user_info['age']}")
    except Exception as e:
        st.error(f"Error rendering dashboard: {e}")


def main(json_file_path="data.json"):
    st.header("Illicit Content Detection System")
    page = st.sidebar.radio(
        "Go to",
        (
            "Signup/Login",
            "Dashboard",
            "Identify Illicit Content",
        ),
        key="page",
    )

    if page == "Signup/Login":
        st.title("Signup/Login Page")
        login_or_signup = st.radio(
            "Select an option", ("Login", "Signup"), key="login_signup"
        )
        if login_or_signup == "Login":
            login(json_file_path)
        else:
            signup(json_file_path)

    elif page == "Dashboard":
        if session_state.get("logged_in"):
            render_dashboard(session_state["user_info"])
        else:
            st.warning("Please login/signup to view the dashboard.")

    elif page == "Identify Illicit Content":
        if session_state.get("logged_in"):
            mappings = {
                "Less than or equal 14,Male": "<span style='color: green; font-size: 18px;'> This content is safe for children under 14 years of age and is classified to be suitable for primarily Male audience.</span>",
                "More than 14,Male": "<span style='color: red; font-size: 18px;'> This content is not safe for children under 14 years of age and is classified to be suitable for primarily Male audience.</span>",
                "Less than or equal to 14,Female": "<span style='color: green; font-size: 18px;'> This content is safe for children under 14 years of age and is classified to be suitable for primarily Female audience.</span>",
                "More than 14,Female": "<span style='color: red; font-size: 18px;'> This content is not safe for children under 14 years of age and is classified to be suitable for primarily Female audience.</span>",
            }

            user_info = session_state["user_info"]
            st.title("Detection of possible illicit content")
            choice = st.radio("Select the type of content", ("Image", "Text"))
            if choice == "Image":
                uploaded_file = st.file_uploader("Upload an image", type=["png", "jpg"])
                if uploaded_file:
                    image_path = f"temp_image_{session_state['user_index']}.png"
                    with open(image_path, "wb") as file:
                        file.write(uploaded_file.getvalue())
                    st.image(
                        uploaded_file, caption="Image", use_column_width=True
                    )
                    result = classify_image(image_path)
                    if result in mappings:
                        st.markdown(mappings[result], unsafe_allow_html=True)
                    else:
                        if "More than 14" in result:
                            if "Male" in result:
                                result = "More than 14,Male"
                            else:
                                result = "More than 14,Female"
                        else:
                            if "Male" in result:
                                result = "Less than or equal 14,Male"
                            else:
                                result = "Less than or equal to 14,Female"
                        st.markdown(mappings[result], unsafe_allow_html=True)
                    os.remove(image_path)
            else:
                text = st.text_area("Enter the text to classify")
                if text:
                    result = classify_text(text)
                    if result in mappings:
                        st.markdown(mappings[result], unsafe_allow_html=True)
                    else:
                        if "More than 14" in result:
                            if "Male" in result:
                                result = "More than 14,Male"
                            else:
                                result = "More than 14,Female"
                        else:
                            if "Male" in result:
                                result = "Less than or equal 14,Male"
                            else:
                                result = "Less than or equal to 14,Female"
                        st.markdown(mappings[result], unsafe_allow_html=True)

        else:
            st.warning("Please login/signup to chat.")


if __name__ == "__main__":

    initialize_database()
    main()
