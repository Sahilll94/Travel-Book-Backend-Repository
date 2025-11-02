// Test script for contributor endpoints
// This script helps test the contributor API endpoints

const axios = require('axios');

// Base URL for your backend
const BASE_URL = 'http://localhost:3000'; // Change this to your actual backend URL

// Test functions
async function testContributorEndpoints() {
    console.log('🚀 Testing Contributor Endpoints...\n');
    
    try {
        // Test 1: Get all contributors (should work without auth)
        console.log('📊 Testing GET /contributors...');
        const contributorsResponse = await axios.get(`${BASE_URL}/contributors`);
        console.log('✅ Contributors fetched successfully!');
        console.log(`   Found ${contributorsResponse.data.contributors.length} contributors\n`);
        
        // Test 2: Get contributor stats
        console.log('📈 Testing GET /contributors/stats...');
        const statsResponse = await axios.get(`${BASE_URL}/contributors/stats`);
        console.log('✅ Stats fetched successfully!');
        console.log(`   Total: ${statsResponse.data.stats.total}, Approved: ${statsResponse.data.stats.approved}\n`);
        
        // Test 3: Submit a test contributor application
        console.log('📝 Testing POST /contributors/submit...');
        const testContributor = {
            name: 'Test Contributor',
            email: 'test@example.com',
            github: 'https://github.com/testuser',
            linkedin: 'https://linkedin.com/in/testuser',
            contributionType: 'Development',
            description: 'I would like to contribute to the frontend development',
            experience: 'Intermediate',
            availability: 'Part-time',
            portfolioUrl: 'https://testuser.dev',
            additionalInfo: 'This is a test submission'
        };
        
        const submitResponse = await axios.post(`${BASE_URL}/contributors/submit`, testContributor);
        console.log('✅ Contributor application submitted successfully!');
        console.log(`   Application ID: ${submitResponse.data.contributorId}\n`);
        
        console.log('🎉 All tests passed! The contributor system is working correctly.\n');
        
        console.log('📌 Next Steps:');
        console.log('1. Start your backend server: npm start');
        console.log('2. Visit your frontend at: http://localhost:5173/contributors');
        console.log('3. Try submitting a contributor application at: http://localhost:5173/contribute');
        console.log('4. Check your email (sahilk64555@gmail.com) for admin notifications');
        
    } catch (error) {
        console.error('❌ Test failed:', error.response?.data?.message || error.message);
        console.log('\n💡 Make sure your backend server is running on', BASE_URL);
        console.log('   You can start it with: npm start');
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    testContributorEndpoints();
}

module.exports = { testContributorEndpoints };
