import { useRef, useState, useEffect } from "react"
import { faCheck, faTimes, faInfoCircle } from "@fortawesome/free-solid-svg-icons"
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome"
import axios from "./api/axios"

const PROFILE_NAME_REGEX = /\S/;
const USER_REGEX = /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/;
const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/;
const REGISTER_URL = "api/users/register";

const Register = () => {
  const nameRef = useRef();
  const userRef = useRef(); //PROMENI SVUDA USER U EMAIL I DODAJ ZA IME
  const errRef = useRef();

  const [name, setName] = useState("")
  const [validProfileName, setValidProfileName] = useState(false);
  const [profileNameFocus, setProfileNameFocus] = useState(false);

  const [user, setUser] = useState(""); //PROMENI SVUDA USER U EMAIL I DODAJ ZA IME
  const [validName, setValidName] = useState(false);
  const [userFocus, setUserFocus] = useState(false);

  const [pwd, setPwd] = useState("");
  const [validPwd, setValidPwd] = useState(false);
  const [pwdFocus, setPwdFocus] = useState(false);

  const [errMsg, setErrMsg] = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    //userRef.current.focus();
    nameRef.current.focus();
  }, []);

  useEffect(() => {
    setValidProfileName(PROFILE_NAME_REGEX.test(name));
  }, [name]);

  useEffect(() => {
    setValidName(USER_REGEX.test(user));
  }, [user]);

  useEffect(() => {
    setValidPwd(PWD_REGEX.test(pwd));
  }, [pwd]);

  useEffect(() => {
    setErrMsg("");
  }, [name, user, pwd]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    // if button enabled with JS hack
    const v1 = USER_REGEX.test(user);
    const v2 = PWD_REGEX.test(pwd);
    const v3 = PROFILE_NAME_REGEX.test(name)
    if (!v1 || !v2 || !v3) {
      setErrMsg("Invalid Entry");
      return;
    }

    try {
      const response = await axios.post(
        REGISTER_URL,
        JSON.stringify({ name: name, email: user, password: pwd }), //PROMENI OVO
        {
          headers: { "Content-Type": "application/json" },
          withCredentials: true,
        }
      );
      console.log(response?.data);
      console.log(response?.accessToken);
      console.log(JSON.stringify(response));
      setSuccess(true);
      //clear state and controlled inputs
      //need value attrib on inputs for this
      setUser("");
      setPwd("");
    } catch (err) {
      if (!err?.response) {
        setErrMsg("No Server Response");
      } else if (err.response?.status === 409) {
        //PROMENI OVO
        setErrMsg("Username Taken");
      } else {
        setErrMsg("Registration Failed");
      }
      errRef.current.focus();
    }
  };
  //PROMENI SVUDA USER U EMAIL I DODAJ ZA IME
  return (
    <>
      {success ? (
        <section>
          <h1>Success!</h1>
          <p>
            <a href="#">Sign In</a>
          </p>
        </section>
      ) : (
        <section>
          <p
            ref={errRef}
            className={errMsg ? "errmsg" : "offscreen"}
            aria-live="assertive"
          >
            {errMsg}
          </p>
          <h1>Register</h1>
          <form onSubmit={handleSubmit}>
            <label htmlFor="name">
              Name:
              <FontAwesomeIcon
                icon={faCheck}
                className={validProfileName ? "valid" : "hide"}
              />
              <FontAwesomeIcon
                icon={faTimes}
                className={validProfileName || !name ? "hide" : "invalid"}
              />
            </label>
            <input
              type="text"
              id="profileName"
              ref={nameRef}
              autoComplete="off"
              onChange={(e) => setName(e.target.value)}
              value={name}
              required
              aria-invalid={validProfileName ? "false" : "true"}
              onFocus={() => setProfileNameFocus(true)}
              onBlur={() => setProfileNameFocus(false)}
            />
            <label htmlFor="username">
              Email:
              <FontAwesomeIcon
                icon={faCheck}
                className={validName ? "valid" : "hide"}
              />
              <FontAwesomeIcon
                icon={faTimes}
                className={validName || !user ? "hide" : "invalid"}
              />
            </label>
            <input
              type="email"
              id="username"
              ref={userRef}
              autoComplete="off"
              onChange={(e) => setUser(e.target.value)}
              value={user}
              required
              aria-invalid={validName ? "false" : "true"}
              onFocus={() => setUserFocus(true)}
              onBlur={() => setUserFocus(false)}
            />
            <label htmlFor="password">
              Password:
              <FontAwesomeIcon
                icon={faCheck}
                className={validPwd ? "valid" : "hide"}
              />
              <FontAwesomeIcon
                icon={faTimes}
                className={validPwd || !pwd ? "hide" : "invalid"}
              />
            </label>
            <input
              type="password"
              id="password"
              onChange={(e) => setPwd(e.target.value)}
              value={pwd}
              required
              aria-invalid={validPwd ? "false" : "true"}
              aria-describedby="pwdnote"
              onFocus={() => setPwdFocus(true)}
              onBlur={() => setPwdFocus(false)}
            />
            <p
              id="pwdnote"
              className={pwdFocus && !validPwd ? "instructions" : "offscreen"}
            >
              <FontAwesomeIcon icon={faInfoCircle} />
              8 to 24 characters.
              <br />
              Must include uppercase and lowercase letters, a number and a
              special character.
              <br />
              Allowed special characters:{" "}
              <span aria-label="exclamation mark">!</span>{" "}
              <span aria-label="at symbol">@</span>{" "}
              <span aria-label="hashtag">#</span>{" "}
              <span aria-label="dollar sign">$</span>{" "}
              <span aria-label="percent">%</span>
            </p>
            <button disabled={!validName || !validPwd ? true : false}>
              Sign Up
            </button>
          </form>
          <p>
            Already registered?
            <br />
            <span className="line">
              {/*put router link here*/}
              <a href="#">Sign In</a>
            </span>
          </p>
        </section>
      )}
    </>
  );
}

export default Register