import { useState, useEffect } from "react";
import { useNavigate, Link, useLocation } from "react-router-dom";
import { useContext } from "react";
import AuthContext from "../context/AuthProvider";
import useAxiosPrivate from "../hooks/useAxiosPrivate";

const Home = () => {
  const { setAuth } = useContext(AuthContext);
  const navigate = useNavigate();

  //TEST
  const [user, setUser] = useState();
  const axiosPrivate = useAxiosPrivate();
  const location = useLocation();

  useEffect(() => {
    let isMounted = true;
    //const controller = new AbortController();

    const getUser = async () => {
      try {
        const response = await axiosPrivate.get("/api/users/current", {
          //signal: controller.signal,
        });
        console.log(response.data);
        isMounted && setUser(response.data);
      } catch (err) {
        console.log('AAAAAAAAAAA')
        console.error(err);
        navigate("/login", { state: { from: location }, replace: true });
      }
      // let test = { name: "Stefan", email: "stefan@gmail.com" };
      // isMounted && setUser(test);
    };

    getUser();

    return () => {
      isMounted = false;
      //controller.abort();
    };
  }, []);
  //TEST

  const logout = async () => {
    // if used in more components, this should be in context
    // axios to /logout endpoint
    setAuth({});
    navigate("/login");
  };

  return (
    <section>
      <h1>Profile</h1>
      <br />
      {user && (
        <form>
          <label htmlFor="name">Name:</label>
          <input
            type="text"
            id="name"
            autoComplete="off"
            value={user?.name}
            disabled
          />
          <label htmlFor="username">Email:</label>
          <input
            type="email"
            id="username"
            autoComplete="off"
            value={user?.email}
            disabled
          />
        </form>
      )}

      <div className="flexGrow">
        <button onClick={logout}>Sign Out</button>
      </div>
    </section>
  );
};

export default Home;
