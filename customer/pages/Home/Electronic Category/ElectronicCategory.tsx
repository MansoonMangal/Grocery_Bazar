import React from "react";
import ElectronicCategoryCard from "./ElectronicCategoryCard";
import { useMediaQuery } from "@mui/material";

const electronics = [
  {
    section: "Fruits_CATEGORIES",
    name: "Fruits",
    image:
      "https://img.freepik.com/free-photo/strawberry-berry-levitating-white-background_485709-57.jpg?uid=R185803845&ga=GA1.1.1558987978.1738592884&semt=ais_hybrid",
    categoryId: "fruits"
  },
  {
    section: "Vegitable_CATEGORIES",
    name: "Vegitable",
    image:
      "https://img.freepik.com/free-photo/green-broccoli-levitating-white-background_485709-79.jpg?uid=R185803845&ga=GA1.1.1558987978.1738592884&semt=ais_hybrid",
    categoryId: "vegitable"
  },
  {
    section: "GROCERY_CATEGORIES",
    name: "Grocery",
    image:
      "https://th.bing.com/th/id/OIP.7pKHWR86dUmUAPUDNULXJQHaE6?w=3788&h=2516&rs=1&pid=ImgDetMain",
    categoryId: "grocery"
  },
  {
    section: "PersonalCare_CATEGORIES",
    name: "PersonalCare",
    image:  
      "https://th.bing.com/th/id/OIP.L0Rgzngh-JbWrwJfXjQoagHaEo?rs=1&pid=ImgDetMain",
    categoryId: "personalcare"
  },
  {
    section: "Daily_CATEGORIES",
    name: "Daily",
    image:
      "https://th.bing.com/th/id/OIP.v8Ss8r_j7puCPuX3QP41ogHaGa?w=221&h=191&c=7&r=0&o=5&dpr=1.5&pid=1.7",
    categoryId: "daily"
  }
];

const ElectronicCategory = () => {
  const isSmallScreen = useMediaQuery("(max-width:600px)");

  return (
    <div className="flex flex-wrap justify-between py-5 lg:px-20 border-b">
      {electronics
        .slice(0, isSmallScreen ? 5 : electronics.length)
        .map((item) => (
          <ElectronicCategoryCard key={item.categoryId} item={item} />
        ))}
    </div>
  );
};

export default ElectronicCategory;
