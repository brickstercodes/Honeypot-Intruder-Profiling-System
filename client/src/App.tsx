import { Route, Switch } from "wouter";
import { Toaster } from "sonner";
import Dashboard from "./pages/Dashboard";
import Home from "./pages/Home";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/login" component={Login} />
        <Route path="/admin" component={Dashboard} />
        <Route component={NotFound} />
      </Switch>
      <Toaster position="bottom-right" theme="dark" richColors />
    </>
  );
}
