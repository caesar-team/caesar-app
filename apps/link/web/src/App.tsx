import { Create } from "./pages/Create.js";
import { View } from "./pages/View.js";

export function App() {
  const isView = window.location.pathname.startsWith("/s/");
  return isView ? <View /> : <Create />;
}
