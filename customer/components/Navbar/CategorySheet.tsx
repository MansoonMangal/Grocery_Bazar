import React from 'react'
import { useNavigate } from 'react-router-dom'
import { Box } from '@mui/material'
import { fruitsandvegitablesLevelTwo } from '../../../data/category/level two/fruitsandvegitablesLevelTwo';
import { groceryLevelTwo } from '../../../data/category/level two/groceryLevelTwo';
import { packagedfoodLevelTwo } from '../../../data/category/level two/packagedfoodLevleTwo';
import { personalcareLevelTwo } from '../../../data/category/level two/personalcareLavelTwo';
import { fruitsandvegitablesLevelThree } from '../../../data/category/level three/fruitsandvegitablesLevelThree';
import { groceryLevelThree } from '../../../data/category/level three/groceryLevelThree';
import { packagedfoodLevelThree } from '../../../data/category/level three/packagedfoodLevelThree';
import { personalcareLevelThree } from '../../../data/category/level three/personalcareLevelThree';

const categoryTwo: { [key: string]: any[] } = {
    fruitsandvegetables: fruitsandvegitablesLevelTwo,
    grocery: groceryLevelTwo,
    packagedfood: packagedfoodLevelTwo,
    personalcare: personalcareLevelTwo,
  };
  
  const categoryThree: { [key: string]: any[] } = {
    fruitsandvegetables: fruitsandvegitablesLevelThree,
    grocery: groceryLevelThree,
    packagedfood: packagedfoodLevelThree,
    personalcare: personalcareLevelThree,
  };
  

const CategorySheet = ({ selectedCategory,toggleDrawer,setShowSheet }: any) => {

const navigate=useNavigate()


    const childCategory = (category: any, parentCategoryId: any) => {
        return category.filter((child: any) => {
            // console.log("Category", parentCategoryId, child)
            return child.parentCategoryId == parentCategoryId
        })

    }
    const handleCategoryClick = (category:string) => {
        if(toggleDrawer){
            toggleDrawer(false)()
        }
        if(setShowSheet){
            setShowSheet(false)
        }
        
        navigate("/products/"+category)
    }
    return (
        <Box className='bg-white shadow-lg  lg:h-[500px] overflow-y-auto'>
            <div className=' flex text-sm flex-wrap'>
                {categoryTwo[selectedCategory]?.map((item: any,index) => 
                <div  key={item.name} className={`p-8 lg:w-[20%] ${index%2==0?"bg-slate-50":"bg-white"}`}>

                    <p className='text-[#00927c] mb-5 font-semibold'>{item.name}</p>

                    <ul className='space-y-3'>
                        {childCategory(categoryThree[selectedCategory], item.categoryId)?.map((item: any) => <div key={item.name}>

                            <li 
                            onClick={()=>handleCategoryClick(item.categoryId)}
                            className='hover:text-[#00927c] cursor-pointer'>
                                {item.name}
                            </li>

                        </div>)}
                    </ul>


                </div>)}
            </div>
        </Box>
    )
}

export default CategorySheet