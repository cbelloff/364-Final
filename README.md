#SI 364: Final Project by Carly Belloff

The name of my database is final_project, so first write createdb final_project in your terminal. 
To run my program after you create the database, copy the following but fill in what is in the % signs with your email and password, so the email sent is from your own email:

export MAIL_PASSWORD=“%”  
export MAIL_USERNAME=“%”

(or use my email and password if you want my program to send you an email from my account: MAIL_USERNAME=“carlyb382@gmail.com” MAIL_PASSWORD=“buddy310”)

To run my program, type the following into your terminal: python3 final.py runserver
Next, type the following link into your browser: http://localhost:5000/

Users will need to import requests and the other modules we have been using in class. 

First you will log in to my program or register if you are a new user. Once you log in, then you will see my form. The goal of my program is to help users keep track of the companies that they are interested in applying to. Therefore, the first form that users will encounter asks where they are looking to apply. In this form, users can search any term into the textbox from a company name to a job title. However, this field is not required as users can simply be interested in looking for jobs in a certain state without caring about the position or company, so we made the state textbox mandatory. Once users submit a search, the Glassdoor API will be called and on this page will appear a list of companies that match the search along with the company logo and the company’s overall rating. If users like what they see, then they can click on the company name (dynamic link) and this will reroute the user to a page that contains more details about the company such as featured reviews (one pro and one con). After reading the Glassdoor reviews, then users can add that company to their wish list or return back to the search page and form a new search query. No matter which option you choose (wish list or return back to search), users will be brought back to the original form page and can see a list of the companies they added to their wish list along with its location (pulled up by a foreign key in the company table) so users know to not search for that company again. However, you can only see this wish list if you click the button “Load List” that I created using AJAX.  In the wish list I decided to add not only the company name, but its location as well because users can be interested in a company such as LinkedIn in NY or they can be interested in LinkedIn CA. Once users enter a new company to their wish list, then that user will be emailed this new company name and its location. Users can also upload their resumes in pdf format on this page as well, so they have easy access to their resume and can view it as they please. 

In my database, there will be a user table, company table, location table, and user_company table. The company table and the location table have a many to many relationship because one location can have many companies and one company can have many locations. Likewise, the user table and the company table have a one to many relationship because one user can be interested in many companies (as user x can be interested in google, microsoft, etc), but a user can only have a given company with that location once, as they cannot have two records for the same company. Therefore, the association table in my program is the user-company table that keeps track of all the companies that each specific user is interested in for each user that utilizes my program, making the user id and company id foreign keys. If users wish to read more glassdoor reviews about their wish list companies, then they can find those companies in the company table and click the link under the column “reviewlink.”

My program is deployed and can be found using the following link: http://ec2-54-175-30-243.compute-1.amazonaws.com
