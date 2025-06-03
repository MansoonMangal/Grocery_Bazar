import React from 'react'
import HomeCategoryCard from './HomeCategoryCard'
import { useAppSelector } from '../../../../Redux Toolkit/Store';

const homeCategory = [
  {
    "name": "Grocery",
    "categoryId": "grocery",
    "parentCategoryName": "Accessories",
    "parentCategoryId": "Accessories",
    "level": 2,
    "section": "SHOP_BY_CATEGORIES",
    image: "https://img.freepik.com/free-photo/shopping-cart-full-with-groceries-dark-backgrounds_1268-29508.jpg?uid=R185803845&ga=GA1.1.1558987978.1738592884&semt=ais_hybrid"
  },
  {
    "name": "Personal Care",
    "categoryId": "personal care",
    "parentCategoryName": "Furniture",
    "parentCategoryId": "furniture",
    "level": 2,
    "section": "SHOP_BY_CATEGORIES",
    image: "https://img.freepik.com/free-vector/realistic-natural-cosmetic-advertisement_52683-8093.jpg?uid=R185803845&ga=GA1.1.1558987978.1738592884&semt=ais_hybrid"
  },
  {
    "parentCategoryId": "women",
    "level": 2,
    "name": "Daily Essentials",
    "categoryId": "women_sports_active_wear",
    "section": "SHOP_BY_CATEGORIES",
    image: "https://img.freepik.com/premium-photo/mouthwash-other-oral-hygiene-products-colored-table-top-view-with-copy-space-flat-lay-dental-hygiene-oral-care-products-space-text-light-background-concept_79075-26293.jpg?uid=R185803845&ga=GA1.1.1558987978.1738592884&semt=ais_hybrid"
  },
  {
    "parentCategoryId": "women",
    "level": 2,
    "name": "Packaged Food",
    "categoryId": "packagedfood",
    "section": "SHOP_BY_CATEGORIES",
    image: "https://img.freepik.com/free-vector/healthy-food-packaging-set_1284-23304.jpg?uid=R185803845&ga=GA1.1.1558987978.1738592884&semt=ais_hybrid"
  }
];

const HomeCategory = () => {
  const { homePage } = useAppSelector((store) => store);

  return (
    <div className='flex justify-center gap-7 flex-wrap'>
      {/* Map over the static 'homeCategory' data */}
      {homeCategory.map((item) => (
        <HomeCategoryCard key={item.categoryId} item={item} />
      ))}
    </div>
  );
}

export default HomeCategory;
