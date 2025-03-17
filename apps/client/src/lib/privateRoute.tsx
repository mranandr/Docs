import { Route, Redirect } from "react-router-dom";
import APP_ROUTE from "@/lib/app-route.ts";

const PrivateRoute = ({ component: Component, ...rest }) => (
  <Route
    {...rest}
    render={(props) =>
      localStorage.getItem("authToken") ? (
        <Component {...props} />
      ) : (
        <Redirect to={APP_ROUTE.AUTH.LOGIN} />
      )
    }
  />
);

export default PrivateRoute;