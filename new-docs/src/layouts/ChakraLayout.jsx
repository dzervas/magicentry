import { ChakraProvider, defaultSystem } from "@chakra-ui/react"
import React from "react";
import ReactDOM from "react-dom/client";

export default function ChakraLayout({ children }) {
  return (
  <React.StrictMode>
    <ChakraProvider value={defaultSystem}>
      {children}
    </ChakraProvider>
  </React.StrictMode>,
  )
}
