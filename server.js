const express = require('express');
const cors = require('cors');
const { GoogleSpreadsheet } = require('google-spreadsheet');
const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Initialize express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: 'https://nans-dashboard.netlify.app', 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-auth-token'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// FIXED: Properly configure static file serving with absolute path
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use('/images', express.static('public/images'));
console.log(`Serving static files from: ${PUBLIC_DIR}`);

// Create directory for images with absolute path
const IMAGES_DIR = path.join(__dirname, 'public', 'images');
fs.ensureDirSync(IMAGES_DIR);
console.log(`Images directory: ${IMAGES_DIR}`);

// List existing images on startup
try {
  const files = fs.readdirSync(IMAGES_DIR);
  console.log(`Found ${files.length} existing image files`);
  files.forEach(file => console.log(`- ${file}`));
} catch (error) {
  console.error('Error reading images directory:', error);
}

// Authentication middleware
const auth = (req, res, next) => {
  // Get token from header
  const token = req.header('x-auth-token');

  // Check if no token
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token, authorization denied' });
  }

  // Verify token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Token is not valid' });
  }
};

// Role-based middleware
const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Access denied. Admin only.' });
  }
};

// Login route
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Check for admin credentials
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const payload = {
      user: {
        id: 'admin-id',
        username: username,
        role: 'admin'
      }
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '24h' },
      (err, token) => {
        if (err) throw err;
        res.json({ 
          success: true, 
          token,
          user: {
            username: username,
            role: 'admin'
          }
        });
      }
    );
    return;
  }

  // Check for user credentials
  if (username === process.env.USER_USERNAME && password === process.env.USER_PASSWORD) {
    const payload = {
      user: {
        id: 'user-id',
        username: username,
        role: 'user'
      }
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '24h' },
      (err, token) => {
        if (err) throw err;
        res.json({ 
          success: true, 
          token,
          user: {
            username: username,
            role: 'user'
          }
        });
      }
    );
    return;
  }

  // Invalid credentials
  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// Verify token route
app.get('/api/verify-token', auth, (req, res) => {
  res.json({ 
    success: true, 
    user: {
      username: req.user.username,
      role: req.user.role
    }
  });
});

// Logout route
app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// Enhanced attachment parsing
function parseAttachments(attachmentString, applicantId) {
  console.log(`\n=== Parsing attachments for applicant ${applicantId} ===`);
  console.log(`Raw attachment string: ${attachmentString ? attachmentString.substring(0, 100) + '...' : 'NULL'}`);
  
  if (!attachmentString || typeof attachmentString !== 'string') {
    console.log('No valid attachment string found.');
    return { urls: [] };
  }

  try {
    const attachments = [];
    
    // FIXED: Updated regex to properly capture URLs without trailing parameters
    const urlRegex = /download_(?:url|small_url|medium_url|large_url)=(https:\/\/[^?,\}]+)/g;
    let match;
    
    while ((match = urlRegex.exec(attachmentString)) !== null) {
      const urlType = match[0].split('=')[0];
      const url = match[1];
      
      attachments.push({
        type: urlType,
        url: url
      });
      console.log(`Found URL: ${urlType} = ${url.substring(0, 30)}...`);
    }
    
    // Sort by quality preference
    attachments.sort((a, b) => {
      const priority = {
        'download_medium_url': 1,
        'download_url': 2,
        'download_large_url': 3,
        'download_small_url': 4
      };
      return priority[a.type] - priority[b.type];
    });
    
    // Extract filename if available
    const filenameMatch = attachmentString.match(/filename=([^,}]+)/);
    const filename = filenameMatch ? filenameMatch[1] : null;
    console.log(`Filename: ${filename || 'Not found'}`);
    
    // Extract mimetype if available
    const mimeMatch = attachmentString.match(/mimetype=([^,}]+)/);
    const mimetype = mimeMatch ? mimeMatch[1] : null;
    console.log(`MIME type: ${mimetype || 'Not found'}`);
    
    console.log(`Total URLs found: ${attachments.length}`);
    console.log('=== End of attachment parsing ===\n');
    
    return {
      urls: attachments,
      filename,
      mimetype
    };
  } catch (error) {
    console.error('Attachment parsing error:', error);
    return { urls: [] };
  }
}

// Improved image download handler with proper ID handling
async function downloadImage(url, applicantId) {
  console.log(`\n=== Starting image download for applicant ${applicantId} ===`);
  console.log(`URL: ${url.substring(0, 50)}...`);
  
  try {
    // Check if URL is valid
    if (!url.startsWith('http')) {
      console.error('Invalid URL format:', url.substring(0, 30) + '...');
      return null;
    }
    
    // FIXED: Use a sanitized version of the actual applicantId for files
    const safeId = String(applicantId).replace(/[^a-zA-Z0-9_-]/g, '_');
    
    // Clean up any existing images for this applicant
    const existingFiles = fs.readdirSync(IMAGES_DIR).filter(file => 
      file.startsWith(`applicant_${safeId}`)
    );
    existingFiles.forEach(file => fs.unlinkSync(path.join(IMAGES_DIR, file)));
    
    console.log('Making HTTP request to get image...');
    
    const response = await axios({
      method: 'GET',
      url: url,
      responseType: 'arraybuffer',
      timeout: 15000 // 15 seconds timeout
    });
    
    console.log('Image download successful!');
    console.log(`Response status: ${response.status}`);
    console.log(`Content type: ${response.headers['content-type']}`);
    console.log(`Content length: ${response.data.length} bytes`);
    
    // Determine file extension from content-type
    const contentType = response.headers['content-type'];
    let extension = 'jpg'; // Default
    
    if (contentType) {
      if (contentType.includes('jpeg') || contentType.includes('jpg')) {
        extension = 'jpg';
      } else if (contentType.includes('png')) {
        extension = 'png';
      } else if (contentType.includes('gif')) {
        extension = 'gif';
      }
    }
    
    // FIXED: Create a unique filename using the safe ID
    const filename = `applicant_${safeId}.${extension}`;
    const filepath = path.join(IMAGES_DIR, filename);
    
    // Write the file
    console.log(`Writing image to: ${filepath}`);
    await fs.writeFile(filepath, response.data);
    
    // Verify file was written
    try {
      const stats = await fs.stat(filepath);
      console.log(`File written successfully! Size: ${stats.size} bytes`);
      
      // List all files in the directory after saving
      const files = await fs.readdir(IMAGES_DIR);
      console.log(`Directory now contains ${files.length} files`);
    } catch (verifyError) {
      console.error('Error verifying file was written:', verifyError);
    }
    
    // FIXED: Return the proper URL for the image that will work in the frontend
    const publicUrl = `/images/${filename}`;
    console.log(`Public URL: ${publicUrl}`);
    console.log('=== Image download complete ===\n');
    
    return publicUrl;
  } catch (error) {
    console.error('=== ERROR DOWNLOADING IMAGE ===');
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    
    if (error.response) {
      console.error('Error status:', error.response.status);
      console.error('Error headers:', JSON.stringify(error.response.headers));
      console.error('Error data:', typeof error.response.data === 'object' ? 
                  JSON.stringify(error.response.data).substring(0, 200) + '...' : 
                  'Binary data');
    } else if (error.request) {
      console.error('No response received. Request details:', 
                   JSON.stringify(error.request).substring(0, 200) + '...');
    } else {
      console.error('Error setting up request:', error.message);
    }
    
    if (error.config) {
      console.error('Request URL:', error.config.url);
      console.error('Request method:', error.config.method);
    }
    
    console.error('=== End of error report ===\n');
    return null;
  }
}

// Helper function to debug field values from spreadsheet
function debugFieldValues(rows, fieldName) {
  console.log(`\n===== Debugging field: ${fieldName} =====`);
  
  // Count occurrences of each value
  const valueCounts = {};
  
  rows.forEach((row, index) => {
    const rawValue = row[fieldName];
    const valueType = typeof rawValue;
    const trimmedValue = (rawValue || '').toString().trim();
    
    // Add to counts
    valueCounts[trimmedValue] = (valueCounts[trimmedValue] || 0) + 1;
    
    // Log the first 5 items for detailed inspection
    if (index < 5) {
      console.log(`Row ${index + 1}:`);
      console.log(`  Raw value: "${rawValue}"`);
      console.log(`  Type: ${valueType}`);
      console.log(`  Trimmed: "${trimmedValue}"`);
      console.log(`  Lowercase: "${trimmedValue.toLowerCase()}"`);
      console.log(`  Is "yes"?: ${trimmedValue.toLowerCase() === 'yes'}`);
      console.log('---');
    }
  });
  
  // Log value counts
  console.log('Value counts:');
  Object.entries(valueCounts).forEach(([value, count]) => {
    console.log(`  "${value}": ${count} occurrences`);
  });
  
  console.log('===============================\n');
}

// Connect to Google Sheets with enhanced error logging
async function getSheetData() {
  console.log('\n=== Starting Google Sheets connection ===');
  
  try {
    // Log the sheet ID (partially censored for security)
    const sheetId = process.env.GOOGLE_SHEET_ID;
    if (!sheetId) {
      throw new Error('GOOGLE_SHEET_ID environment variable is not set');
    }
    console.log(`Connecting to Google Sheet: ${sheetId.substring(0, 5)}...${sheetId.substring(sheetId.length - 5)}`);
    
    // Initialize the sheet
    const doc = new GoogleSpreadsheet(process.env.GOOGLE_SHEET_ID);
    
    // Log auth attempt
    console.log('Attempting authentication...');
    const serviceAccountEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
    if (!serviceAccountEmail) {
      throw new Error('GOOGLE_SERVICE_ACCOUNT_EMAIL environment variable is not set');
    }
    
    const privateKey = process.env.GOOGLE_PRIVATE_KEY;
    if (!privateKey) {
      throw new Error('GOOGLE_PRIVATE_KEY environment variable is not set');
    }
    
    // Authenticate
    await doc.useServiceAccountAuth({
      client_email: serviceAccountEmail,
      private_key: privateKey.replace(/\\n/g, '\n'),
    });
    
    console.log('Authentication successful');
    
    // Load document info
    console.log('Loading document info...');
    await doc.loadInfo(); // loads document properties and worksheets
    
    console.log(`Document title: ${doc.title}`);
    console.log(`Total worksheets: ${doc.sheetCount}`);
    
    // Get the first sheet
    console.log('Accessing first worksheet...');
    const sheet = doc.sheetsByIndex[0];
    console.log(`Worksheet title: ${sheet.title}`);
    console.log(`Worksheet row count: ${sheet.rowCount}`);
    
    // Get all rows
    console.log('Fetching rows...');
    const rows = await sheet.getRows();
    console.log(`Retrieved ${rows.length} rows`);
    
    // Sample the first row data
    if (rows.length > 0) {
      console.log('First row keys:', Object.keys(rows[0]).slice(0, 10).join(', ') + '...');
      
      // Check if _attachments field exists
      if (rows[0]['_attachments']) {
        console.log('_attachments field found in data!');
        console.log('Sample attachment data (truncated):', 
                   rows[0]['_attachments'].substring(0, 100) + '...');
      } else {
        console.warn('WARNING: No _attachments field found in data! Image download may not work.');
      }
      
      // FIXED: Check if _id field exists
      if (rows[0]['_id']) {
        console.log('_id field found in data!');
        console.log('Sample _id value:', rows[0]['_id']);
      } else {
        console.warn('WARNING: No _id field found! Using row index or alternative ID.');
      }
      
      // Check if parent/caregiver fields exist
      const parentFields = [
        'parents_info/caregiver_type',
        'parents_info/father_name',
        'parents_info/father_occupation',
        'parents_info/father_phone',
                'parents_info/mother_name',
        'parents_info/mother_occupation',
        'parents_info/mother_phone',
        'parents_info/guardian_name',
        'parents_info/guardian_occupation',
        'parents_info/guardian_phone',
        'parents_info_caregiver_type',
        'parents_info_father_name',
        'parents_info_father_occupation',
        'parents_info_father_phone',
        'parents_info_mother_name',
        'parents_info_mother_occupation',
        'parents_info_mother_phone',
        'parents_info_guardian_name',
        'parents_info_guardian_occupation',
        'parents_info_guardian_phone'
      ];
      
      // Check which parent/caregiver fields exist in the data
      const existingParentFields = parentFields.filter(field => field in rows[0]);
      if (existingParentFields.length > 0) {
        console.log('Parent/caregiver fields found in data:', existingParentFields.join(', '));
      } else {
        console.warn('WARNING: No parent/caregiver fields found in data!');
      }
    }
    
    console.log('=== Google Sheets connection complete ===\n');
    return rows;
  } catch (error) {
    console.error('\n=== ERROR ACCESSING GOOGLE SHEETS ===');
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error code:', error.code);
    
    // Log environment variables (partially obscured for security)
    console.log('\n=== Environment variables check ===');
    const sheetId = process.env.GOOGLE_SHEET_ID || 'Not set';
    const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || 'Not set';
    const privateKey = process.env.GOOGLE_PRIVATE_KEY;
    
    console.log(`Sheet ID: ${sheetId ? 
               `${sheetId.substring(0, 5)}...${sheetId.substring(sheetId.length - 5) || ''}` :
               'Not set'}`);
    
    console.log(`Service Account Email: ${email ? 
               `${email.substring(0, 3)}...${email.substring(email.indexOf('@')) || ''}` :
               'Not set'}`);
    
    console.log(`Private Key set: ${privateKey ? 'Yes (Length: ' + privateKey.length + ')' : 'No'}`);
    
    if (privateKey) {
      console.log('Private key appears to be in correct format:', 
                 privateKey.includes('\\n') ? 'Contains escaped newlines (\\n)' : 'No escaped newlines');
    }
    
    console.error('=== End of Google Sheets error report ===\n');
    throw error;
  }
}

// Helper function to normalize institution names
function normalizeInstitution(institution) {
  if (!institution) return '';
  
  // Trim and standardize case to Title Case
  let normalized = institution.trim();
  
  // Handle common abbreviations and misspellings
  const replacements = {
    'UG': 'University of Ghana',
    'KNUST': 'Kwame Nkrumah University of Science and Technology',
    'UCC': 'University of Cape Coast',
    'UENR': 'University of Energy and Natural Resources',
    'UDS': 'University for Development Studies',
    'UPSA': 'University of Professional Studies, Accra',
    // Add more replacements as needed
  };
  
  // Check if the normalized text is a known abbreviation that needs replacement
  if (replacements[normalized.toUpperCase()]) {
    return replacements[normalized.toUpperCase()];
  }
  
  // Convert to title case for consistency
  return normalized.replace(/\w\S*/g, (txt) => {
    return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
  });
}

// Helper function to normalize institution locations
function normalizeLocation(location) {
  if (!location) return '';
  
  // Trim and standardize case to Title Case
  let normalized = location.trim();
  
  // Handle common misspellings or variations of locations
  const replacements = {
    'ACCRA': 'Accra',
    'K\'SI': 'Kumasi',
    'KUMASI': 'Kumasi',
    'TAMALE': 'Tamale',
    'C.COAST': 'Cape Coast',
    'CAPE COAST': 'Cape Coast',
    // Add more replacements as needed
  };
  
  // Check if the normalized text is in the replacements dictionary
  if (replacements[normalized.toUpperCase()]) {
    return replacements[normalized.toUpperCase()];
  }
  
  // Convert to title case for consistency
  return normalized.replace(/\w\S*/g, (txt) => {
    return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
  });
}

// Helper function to normalize educational level
function normalizeLevel(level) {
  if (!level) return '';
  
  // Trim and standardize
  let normalized = level.trim();
  
  // Handle common abbreviations and variations
  const replacements = {
    '100': 'Level 100',
    '200': 'Level 200',
    '300': 'Level 300',
    '400': 'Level 400',
    '500': 'Level 500',
    '600': 'Level 600',
    'L100': 'Level 100',
    'L200': 'Level 200',
    'L300': 'Level 300',
    'L400': 'Level 400',
    'LEVEL 1': 'Level 100',
    'LEVEL 2': 'Level 200',
    'LEVEL 3': 'Level 300',
    'LEVEL 4': 'Level 400',
    'FIRST YEAR': 'Level 100',
    'SECOND YEAR': 'Level 200',
    'THIRD YEAR': 'Level 300',
    'FOURTH YEAR': 'Level 400',
    'MASTERS': 'Masters',
    'PHD': 'PhD',
    'DIPLOMA': 'Diploma',
    // Add more replacements as needed
  };
  
  // Check if the normalized text is in the replacements dictionary
  if (replacements[normalized.toUpperCase()]) {
    return replacements[normalized.toUpperCase()];
  }
  
  return normalized;
}

// Helper function to normalize gender values
function normalizeGender(gender) {
  if (!gender) return 'Not Specified';
  
  // Trim and convert to lowercase for comparison
  const normalized = gender.trim().toLowerCase();
  
  // Handle common variations
  if (normalized === 'm' || normalized === 'male') {
    return 'Male';
  } else if (normalized === 'f' || normalized === 'female') {
    return 'Female';
  } else if (normalized === '') {
    return 'Not Specified';
  } else {
    // Convert to Title Case for other values
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }
}

// Helper function to normalize caregiver type
function normalizeCaregiverType(type) {
  if (!type) return '';
  
  // Trim and convert to lowercase for comparison
  const normalized = type.trim().toLowerCase();
  
  // Handle common variations
  if (normalized === 'parent' || normalized === 'parents' || normalized === 'both parents') {
    return 'Parents';
  } else if (normalized === 'guardian' || normalized === 'guardians') {
    return 'Guardian';
  } else if (normalized === 'father' || normalized === 'father only') {
    return 'Father';
  } else if (normalized === 'mother' || normalized === 'mother only') {
    return 'Mother';
  } else {
    // Convert to Title Case for other values
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }
}

// Modified applicants endpoint with authentication
app.get('/api/applicants', auth, async (req, res) => {
  console.log('\n=== Handling /api/applicants request ===');
  console.log(`Request by user: ${req.user.username} (${req.user.role})`);
  
  try {
    const rows = await getSheetData();
    
    // Debug the level field to see raw values
    debugFieldValues(rows, 'personal_details/level');
    
    // Debug the gender field to see raw values
    debugFieldValues(rows, 'personal_details/Sex');
    
    // Debug caregiver type field if it exists
    if (rows.length > 0 && (rows[0]['parents_info/caregiver_type'] || rows[0]['parents_info_caregiver_type'])) {
      debugFieldValues(rows, rows[0]['parents_info/caregiver_type'] ? 'parents_info/caregiver_type' : 'parents_info_caregiver_type');
    }
    
    // FIXED: Debug the _id field if it exists
    if (rows.length > 0 && rows[0]['_id']) {
      debugFieldValues(rows, '_id');
    }
    
    console.log(`Processing ${rows.length} applicants with image downloads...`);
    
    // Track image download statistics
    let imageDownloads = {
      attempts: 0,
      successful: 0,
      failed: 0
    };
    
    // Transform Google Sheets data with proper normalization and image downloading
    const applicants = await Promise.all(rows.map(async (row, index) => {
      console.log(`\n--- Processing applicant ${index + 1}/${rows.length}: ${row['personal_details/firstname'] || 'Unknown'} ${row['personal_details/surname'] || 'Unknown'} ---`);
      
      // FIXED: Extract a reliable ID from the data or generate one
      // First try _id, then _uuid, then generate one from index and name
      const applicantId = row['_id'] || 
                         row['_uuid'] || 
                         `index_${index}_${row['personal_details/firstname'] || ''}_${row['personal_details/surname'] || ''}`;
      
      console.log(`Using applicant ID: ${applicantId}`);
      
      // Normalize district data
      let district = row['personal_details/district'] || '';
      if (district === 'district1') district = 'Nzema';
      else if (district === 'district2') district = 'East Jomoro';
      else if (district === 'district3') district = 'Ellembelle';
      
      // Normalize program - capitalize and trim spaces
      let program = row['personal_details/program'] || '';
      program = program.trim().toUpperCase();
      
      // Normalize institution and institution location
      const university = normalizeInstitution(row['personal_details/institution']);
      const universityLocation = normalizeLocation(row['personal_details/institution_place']);
      
      // Normalize educational level
      const level = normalizeLevel(row['personal_details/level']);
      
      // Normalize gender
      const gender = normalizeGender(row['personal_details/Sex']);
      
      // Check membership status properly with better handling
      const memberStatus = (row['general_questions/member_of_nans'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No';
      
      // Extract and normalize caregiver information
      // First check which field naming convention is used (with slash or underscore)
      const useSlashFormat = 'parents_info/caregiver_type' in row;
      
      // Get caregiver type
      const caregiverTypeField = useSlashFormat ? 'parents_info/caregiver_type' : 'parents_info_caregiver_type';
      const caregiverType = normalizeCaregiverType(row[caregiverTypeField] || '');
      
      // Get father information
      const fatherNameField = useSlashFormat ? 'parents_info/father_name' : 'parents_info_father_name';
      const fatherOccupationField = useSlashFormat ? 'parents_info/father_occupation' : 'parents_info_father_occupation';
      const fatherPhoneField = useSlashFormat ? 'parents_info/father_phone' : 'parents_info_father_phone';
      
      const fatherName = row[fatherNameField] || '';
      const fatherOccupation = row[fatherOccupationField] || '';
      const fatherPhone = row[fatherPhoneField] || '';
      
      // Get mother information
      const motherNameField = useSlashFormat ? 'parents_info/mother_name' : 'parents_info_mother_name';
      const motherOccupationField = useSlashFormat ? 'parents_info/mother_occupation' : 'parents_info_mother_occupation';
      const motherPhoneField = useSlashFormat ? 'parents_info/mother_phone' : 'parents_info_mother_phone';
      
      const motherName = row[motherNameField] || '';
      const motherOccupation = row[motherOccupationField] || '';
      const motherPhone = row[motherPhoneField] || '';
      
      // Get guardian information
      const guardianNameField = useSlashFormat ? 'parents_info/guardian_name' : 'parents_info_guardian_name';
      const guardianOccupationField = useSlashFormat ? 'parents_info/guardian_occupation' : 'parents_info_guardian_occupation';
      const guardianPhoneField = useSlashFormat ? 'parents_info/guardian_phone' : 'parents_info_guardian_phone';
      
      const guardianName = row[guardianNameField] || '';
      const guardianOccupation = row[guardianOccupationField] || '';
      const guardianPhone = row[guardianPhoneField] || '';
      
      // Handle image attachment - get the column with attachments
      let profileImage = null;
      const attachmentField = row['_attachments'];
      
      // Check if there are attachments and process them
      if (attachmentField) {
        const parsedAttachments = parseAttachments(attachmentField, applicantId);
        
        // Find an appropriate URL to download - prefer medium size for balance of quality and speed
        let imageUrl = null;
        if (parsedAttachments.urls.length > 0) {
          imageUrl = parsedAttachments.urls[0].url;
          console.log(`Selected URL (${parsedAttachments.urls[0].type}): ${imageUrl.substring(0, 50)}...`);
          
          // FIXED: Use the extracted applicantId for the image download
          imageDownloads.attempts++;
          profileImage = await downloadImage(imageUrl, applicantId);
          
          if (profileImage) {
            imageDownloads.successful++;
            console.log(`✓ Image download successful for applicant ${applicantId}`);
          } else {
            imageDownloads.failed++;
            console.log(`✗ Image download failed for applicant ${applicantId}`);
          }
        } else {
          console.log(`No suitable image URL found for applicant ${applicantId}`);
        }
      } else {
        console.log(`No attachment data found for applicant ${applicantId}`);
      }
      
      console.log(`--- Finished processing applicant ${index + 1} ---\n`);
      
      return {
        // FIXED: Include the ID in the returned object
        id: applicantId,
        name: `${row['personal_details/firstname'] || ''} ${row['personal_details/middlename'] ||''} ${row['personal_details/surname'] || ''}`,
        age: parseInt(row['personal_details/calc_age'] || '0'),
        dob: row['personal_details/dob'] || '',
        gender: gender,
        email: row['personal_details/email'] || '',
        phone: row['personal_details/telephone'] || '',
                whatsapp: row['personal_details/whatsapp'] || '',
        funder: row['general_questions/current_scholarship_funder'] || '',
        university: university,
        universityLocation: universityLocation,
        program: program,
        level: level,
        district: district,
        hometown: row['personal_details/hometown'] || '',
        yearBegin: row['personal_details/year_begin'] || '',
        yearEnd: row['personal_details/year_end'] || '',
        member: memberStatus,
        heardAboutNans: row['general_questions/heard_about_nans'] || '',
        holdPosition: (row['general_questions/hold_position'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        supportNans: row['general_questions/support_nans'] || '',
        specialSkills: row['general_questions/special_skills'] || '',
        interests: row['general_questions/interests'] || '',
        hadScholarship: (row['general_questions/had_scholarship_before'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        currentlyOnScholarship: (row['general_questions/currently_on_scholarship'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        profileImage: profileImage, // Add the profile image URL
        imageStatus: profileImage ? 'success' : (attachmentField ? 'failed' : 'none'),
        
        // Add caregiver information
        caregiverType: caregiverType,
        fatherName: fatherName,
        fatherOccupation: fatherOccupation,
        fatherPhone: fatherPhone,
        motherName: motherName,
        motherOccupation: motherOccupation,
        motherPhone: motherPhone,
        guardianName: guardianName,
        guardianOccupation: guardianOccupation,
        guardianPhone: guardianPhone
      };
    }));
    
    // Final verification of images directory contents after all processing
    try {
      const files = fs.readdirSync(IMAGES_DIR);
      console.log(`\nFinal verification - images directory contains ${files.length} files:`);
      files.slice(0, 10).forEach(file => console.log(`- ${file}`));
      if (files.length > 10) {
        console.log(`... and ${files.length - 10} more files`);
      }
    } catch (error) {
      console.error('Error reading images directory during final verification:', error);
    }
    
    // Log image download statistics
    console.log('\n=== Image Download Summary ===');
    console.log(`Total attempts: ${imageDownloads.attempts}`);
    console.log(`Successful: ${imageDownloads.successful}`);
    console.log(`Failed: ${imageDownloads.failed}`);
    console.log(`Success rate: ${imageDownloads.attempts > 0 ? 
              Math.round((imageDownloads.successful / imageDownloads.attempts) * 100) : 0}%`);
    
    console.log(`\nReturning ${applicants.length} normalized applicants with images`);
    res.json({ 
      success: true, 
      data: applicants,
      imageStats: {
        total: applicants.length,
        withImages: applicants.filter(a => a.profileImage).length,
        failed: applicants.filter(a => a.imageStatus === 'failed').length
      }
    });
  } catch (error) {
    console.error('Error fetching applicant data:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Enhanced dashboard stats endpoint - public access for basic stats
app.get('/api/dashboard-stats', async (req, res) => {
  try {
    console.log('Handling /api/dashboard-stats request');
    const rows = await getSheetData();
    
    // Debug the level field to see raw values
    debugFieldValues(rows, 'personal_details/level');
    
    // Debug the gender field to see raw values
    debugFieldValues(rows, 'personal_details/Sex');
    
    // Debug caregiver type field if it exists
    if (rows.length > 0 && (rows[0]['parents_info/caregiver_type'] || rows[0]['parents_info_caregiver_type'])) {
      debugFieldValues(rows, rows[0]['parents_info/caregiver_type'] ? 'parents_info/caregiver_type' : 'parents_info_caregiver_type');
    }
    
    // Transform the data into the required statistics with proper normalization
    const applicants = rows.map((row, index) => {
      // FIXED: Extract a reliable ID from the data or generate one
      const applicantId = row['_id'] || 
                         row['_uuid'] || 
                         `index_${index}_${row['personal_details/firstname'] || ''}_${row['personal_details/surname'] || ''}`;
      
      // Normalize district data
      let district = row['personal_details/district'] || '';
      if (district === 'district1') district = 'Nzema';
      else if (district === 'district2') district = 'East Jomoro';
      else if (district === 'district3') district = 'Ellembelle';
      
      // Normalize program data - capitalize and trim spaces
      let program = row['personal_details/program'] || '';
      program = program.trim().toUpperCase();
      
      // Normalize institution and institution location
      const university = normalizeInstitution(row['personal_details/institution']);
      const universityLocation = normalizeLocation(row['personal_details/institution_place']);
      
      // Normalize educational level
      const level = normalizeLevel(row['personal_details/level']);
      
      // Normalize gender 
      const gender = normalizeGender(row['personal_details/Sex']);
      
      // Check membership status
      const isMember = (row['general_questions/member_of_nans'] || '').trim().toLowerCase() === 'yes';
      
      // Check scholarship status
      const hadScholarship = (row['general_questions/had_scholarship_before'] || '').trim().toLowerCase() === 'yes';
      const currentlyOnScholarship = (row['general_questions/currently_on_scholarship'] || '').trim().toLowerCase() === 'yes';
      
      // Extract and normalize caregiver information
      // First check which field naming convention is used (with slash or underscore)
      const useSlashFormat = 'parents_info/caregiver_type' in row;
      
      // Get caregiver type
      const caregiverTypeField = useSlashFormat ? 'parents_info/caregiver_type' : 'parents_info_caregiver_type';
      const caregiverType = normalizeCaregiverType(row[caregiverTypeField] || '');
      
      return {
        // FIXED: Include the ID in the returned object
        id: applicantId,
        age: parseInt(row['personal_details/calc_age'] || '0'),
        gender: gender,
        university: university,
        universityLocation: universityLocation,
        program: program,
        level: level,
        district: district,
        heardAboutNans: row['general_questions/heard_about_nans'] || '',
        holdPosition: (row['general_questions/hold_position'] || '').trim().toLowerCase() === 'yes',
        isMember: isMember,
        hadScholarship: hadScholarship,
        currentlyOnScholarship: currentlyOnScholarship,
        caregiverType: caregiverType
      };
    });
    
    // Calculate membership statistics
    const members = applicants.filter(a => a.isMember).length;
    const nonMembers = applicants.length - members;
    
    // Process gender statistics
    const genders = {};
    applicants.forEach(applicant => {
      const gender = applicant.gender;
      genders[gender] = (genders[gender] || 0) + 1;
    });
    
    // Process age distribution
    const ageGroups = {
      '0-14': 0,
      '15-20': 0,
      '21-25': 0,
      '26-30': 0,
      '31-35': 0,
      '36+': 0
    };
    
    applicants.forEach(applicant => {
      const age = applicant.age;
      if (age >= 0 && age <= 14) ageGroups['0-14']++;
      else if (age >= 15 && age <= 20) ageGroups['15-20']++;
      else if (age >= 21 && age <= 25) ageGroups['21-25']++;
      else if (age >= 26 && age <= 30) ageGroups['26-30']++;
      else if (age >= 31 && age <= 35) ageGroups['31-35']++;
      else if (age > 35) ageGroups['36+']++;
    });
    
    // Process university statistics
    const universities = {};
    applicants.forEach(applicant => {
      if (applicant.university) {
        universities[applicant.university] = (universities[applicant.university] || 0) + 1;
      }
    });
    
    // Process university location statistics
    const universityLocations = {};
    applicants.forEach(applicant => {
      if (applicant.universityLocation) {
        universityLocations[applicant.universityLocation] = (universityLocations[applicant.universityLocation] || 0) + 1;
      }
    });
    
    // Process program statistics
    const programs = {};
    applicants.forEach(applicant => {
      if (applicant.program) {
        programs[applicant.program] = (programs[applicant.program] || 0) + 1;
      }
    });
    
    // Process level statistics
    const levels = {};
    applicants.forEach(applicant => {
      if (applicant.level) {
        levels[applicant.level] = (levels[applicant.level] || 0) + 1;
      }
    });
    
    // Process district statistics
    const districts = {};
    applicants.forEach(applicant => {
      if (applicant.district) {
        districts[applicant.district] = (districts[applicant.district] || 0) + 1;
      }
    });
    
    // Process referral sources
    const referralSources = {};
    applicants.forEach(applicant => {
      const source = applicant.heardAboutNans;
      if (source) {
        referralSources[source] = (referralSources[source] || 0) + 1;
      }
    });
    
    // Process positions held
    const positionsHeld = { Yes: 0, No: 0 };
    applicants.forEach(applicant => {
      positionsHeld[applicant.holdPosition ? 'Yes' : 'No']++;
    });
    
    // Process scholarship data
    const previousScholarship = applicants.filter(a => a.hadScholarship).length;
    const currentScholarship = applicants.filter(a => a.currentlyOnScholarship).length;
    const noScholarship = applicants.filter(a => !a.hadScholarship && !a.currentlyOnScholarship).length;
    
    // Process caregiver type statistics
    const caregiverTypes = {};
    applicants.forEach(applicant => {
      if (applicant.caregiverType) {
        caregiverTypes[applicant.caregiverType] = (caregiverTypes[applicant.caregiverType] || 0) + 1;
      } else {
        caregiverTypes['Not Specified'] = (caregiverTypes['Not Specified'] || 0) + 1;
      }
    });
    
    res.json({
      success: true,
      data: {
        totalApplicants: applicants.length,
        membership: [
          { name: 'Members', value: members },
          { name: 'Non-members', value: nonMembers },
        ],
        genderDistribution: Object.entries(genders)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        ageDistribution: Object.entries(ageGroups)
          .map(([age, count]) => ({ age, count })),
        universities: Object.entries(universities)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        universityLocations: Object.entries(universityLocations)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        programs: Object.entries(programs)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        levels: Object.entries(levels)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        districts: Object.entries(districts)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        referralSources: Object.entries(referralSources)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value })),
        positionsHeld: Object.entries(positionsHeld)
          .map(([name, value]) => ({ name, value })),
        scholarshipData: [
          { name: 'Previous Scholarship', value: previousScholarship },
          { name: 'Current Scholarship', value: currentScholarship },
          { name: 'No Scholarship', value: noScholarship },
        ],
        caregiverTypes: Object.entries(caregiverTypes)
          .sort((a, b) => b[1] - a[1])
          .map(([name, value]) => ({ name, value }))
      }
    });
  } catch (error) {
    console.error('Error generating dashboard stats:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Image management endpoint with admin-only access
app.get('/api/images', auth, adminOnly, async (req, res) => {
  try {
    console.log(`Handling /api/images request by admin: ${req.user.username}`);
    const files = fs.readdirSync(IMAGES_DIR);

    const images = files.map(file => {
      let applicantId = null;

      if (file.startsWith('applicant_')) {
        const idWithExt = file.substring('applicant_'.length);
        const lastDotIndex = idWithExt.lastIndexOf('.');

        if (lastDotIndex > 0) {
          applicantId = idWithExt.substring(0, lastDotIndex);
        }
      }

      return {
        applicantId: applicantId,
        filename: file,
        url: `/images/${file}`,
        size: fs.statSync(path.join(IMAGES_DIR, file)).size
      };
    });

    res.json(images);
  } catch (err) {
    console.error('Error fetching images:', err);
    res.status(500).json({ error: 'Failed to retrieve images' });
  }
});

// Get single applicant by ID with authentication
app.get('/api/applicants/:id', auth, async (req, res) => {
  try {
    console.log(`Handling /api/applicants/:id request by user: ${req.user.username} (${req.user.role})`);
    const applicantId = req.params.id;
    
    // Get all applicants
    const rows = await getSheetData();
    
    // Transform data to get all applicants
    const applicants = await Promise.all(rows.map(async (row, index) => {
          // Extract ID using the same logic as in the list endpoint
      const rowId = row['_id'] || 
                   row['_uuid'] || 
                   `index_${index}_${row['personal_details/firstname'] || ''}_${row['personal_details/surname'] || ''}`;
      
      // First check which field naming convention is used (with slash or underscore)
      const useSlashFormat = 'parents_info/caregiver_type' in row;
      
      // Get caregiver type
      const caregiverTypeField = useSlashFormat ? 'parents_info/caregiver_type' : 'parents_info_caregiver_type';
      const caregiverType = normalizeCaregiverType(row[caregiverTypeField] || '');
      
      // Get father information
      const fatherNameField = useSlashFormat ? 'parents_info/father_name' : 'parents_info_father_name';
      const fatherOccupationField = useSlashFormat ? 'parents_info/father_occupation' : 'parents_info_father_occupation';
      const fatherPhoneField = useSlashFormat ? 'parents_info/father_phone' : 'parents_info_father_phone';
      
      const fatherName = row[fatherNameField] || '';
      const fatherOccupation = row[fatherOccupationField] || '';
      const fatherPhone = row[fatherPhoneField] || '';
      
      // Get mother information
      const motherNameField = useSlashFormat ? 'parents_info/mother_name' : 'parents_info_mother_name';
      const motherOccupationField = useSlashFormat ? 'parents_info/mother_occupation' : 'parents_info_mother_occupation';
      const motherPhoneField = useSlashFormat ? 'parents_info/mother_phone' : 'parents_info_mother_phone';
      
      const motherName = row[motherNameField] || '';
      const motherOccupation = row[motherOccupationField] || '';
      const motherPhone = row[motherPhoneField] || '';
      
      // Get guardian information
      const guardianNameField = useSlashFormat ? 'parents_info/guardian_name' : 'parents_info_guardian_name';
      const guardianOccupationField = useSlashFormat ? 'parents_info/guardian_occupation' : 'parents_info_guardian_occupation';
      const guardianPhoneField = useSlashFormat ? 'parents_info/guardian_phone' : 'parents_info_guardian_phone';
      
      const guardianName = row[guardianNameField] || '';
      const guardianOccupation = row[guardianOccupationField] || '';
      const guardianPhone = row[guardianPhoneField] || '';
      
      return {
        id: rowId,
        name: `${row['personal_details/firstname'] || ''} ${row['personal_details/middlename'] ||''} ${row['personal_details/surname'] || ''}`,
        firstname: row['personal_details/firstname'] || '',
        middlename: row['personal_details/middlename'] || '',
        surname: row['personal_details/surname'] || '',
        age: parseInt(row['personal_details/calc_age'] || '0'),
        dob: row['personal_details/dob'] || '',
        gender: normalizeGender(row['personal_details/Sex']),
        email: row['personal_details/email'] || '',
        phone: row['personal_details/telephone'] || '',
        whatsapp: row['personal_details/whatsapp'] || '',
        funder: row['general_questions/current_scholarship_funder'] || '',
        university: normalizeInstitution(row['personal_details/institution']),
        universityLocation: normalizeLocation(row['personal_details/institution_place']),
        program: (row['personal_details/program'] || '').trim().toUpperCase(),
        level: normalizeLevel(row['personal_details/level']),
        district: row['personal_details/district'] === 'district1' ? 'Nzema' : 
                 row['personal_details/district'] === 'district2' ? 'East Jomoro' : 
                 row['personal_details/district'] === 'district3' ? 'Ellembelle' : 
                 row['personal_details/district'] || '',
        hometown: row['personal_details/hometown'] || '',
        yearBegin: row['personal_details/year_begin'] || '',
        yearEnd: row['personal_details/year_end'] || '',
        member: (row['general_questions/member_of_nans'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        heardAboutNans: row['general_questions/heard_about_nans'] || '',
        holdPosition: (row['general_questions/hold_position'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        supportNans: row['general_questions/support_nans'] || '',
        specialSkills: row['general_questions/special_skills'] || '',
        interests: row['general_questions/interests'] || '',
        hadScholarship: (row['general_questions/had_scholarship_before'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        currentlyOnScholarship: (row['general_questions/currently_on_scholarship'] || '').trim().toLowerCase() === 'yes' ? 'Yes' : 'No',
        
        // Add caregiver information
        caregiverType: caregiverType,
        fatherName: fatherName,
        fatherOccupation: fatherOccupation,
        fatherPhone: fatherPhone,
        motherName: motherName,
        motherOccupation: motherOccupation,
        motherPhone: motherPhone,
        guardianName: guardianName,
        guardianOccupation: guardianOccupation,
        guardianPhone: guardianPhone,
        
        // Get profile image URL if it exists
        profileImage: `/images/applicant_${String(rowId).replace(/[^a-zA-Z0-9_-]/g, '_')}.jpg`
      };
    }));
    
    // Find the applicant with the matching ID
    const applicant = applicants.find(a => a.id === applicantId);
    
    if (!applicant) {
      return res.status(404).json({ success: false, message: 'Applicant not found' });
    }
    
    // Check if the image file actually exists
    const jpgImagePath = path.join(IMAGES_DIR, `applicant_${String(applicantId).replace(/[^a-zA-Z0-9_-]/g, '_')}.jpg`);
    const pngImagePath = path.join(IMAGES_DIR, `applicant_${String(applicantId).replace(/[^a-zA-Z0-9_-]/g, '_')}.png`);
    
    if (fs.existsSync(jpgImagePath)) {
      applicant.profileImage = `/images/applicant_${String(applicantId).replace(/[^a-zA-Z0-9_-]/g, '_')}.jpg`;
    } else if (fs.existsSync(pngImagePath)) {
      applicant.profileImage = `/images/applicant_${String(applicantId).replace(/[^a-zA-Z0-9_-]/g, '_')}.png`;
    } else {
      applicant.profileImage = null;
    }
    
    res.json({ success: true, data: applicant });
  } catch (error) {
    console.error('Error fetching applicant:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Admin-only endpoint to check server status
app.get('/api/admin/status', auth, adminOnly, (req, res) => {
  try {
    const status = {
      server: {
        uptime: process.uptime(),
        timestamp: Date.now(),
        nodeVersion: process.version,
        memoryUsage: process.memoryUsage(),
      },
      images: {
        directory: IMAGES_DIR,
        exists: fs.existsSync(IMAGES_DIR),
        fileCount: fs.existsSync(IMAGES_DIR) ? fs.readdirSync(IMAGES_DIR).length : 0
      },
      environment: {
        googleSheetId: process.env.GOOGLE_SHEET_ID ? 'Set' : 'Not set',
        googleServiceAccount: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL ? 'Set' : 'Not set',
        googlePrivateKey: process.env.GOOGLE_PRIVATE_KEY ? 'Set' : 'Not set',
        jwtSecret: process.env.JWT_SECRET ? 'Set' : 'Not set',
        adminUsername: process.env.ADMIN_USERNAME ? 'Set' : 'Not set',
        userUsername: process.env.USER_USERNAME ? 'Set' : 'Not set'
      }
    };
    
    res.json({ success: true, data: status });
  } catch (error) {
    console.error('Error getting server status:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Environment variables:');
  console.log(`- GOOGLE_SHEET_ID: ${process.env.GOOGLE_SHEET_ID ? '✓ Set' : '✗ Not set'}`);
  console.log(`- GOOGLE_SERVICE_ACCOUNT_EMAIL: ${process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL ? '✓ Set' : '✗ Not set'}`);
  console.log(`- GOOGLE_PRIVATE_KEY: ${process.env.GOOGLE_PRIVATE_KEY ? '✓ Set' : '✗ Not set'}`);
  console.log(`- JWT_SECRET: ${process.env.JWT_SECRET ? '✓ Set' : '✗ Not set'}`);
  console.log(`- ADMIN_USERNAME: ${process.env.ADMIN_USERNAME ? '✓ Set' : '✗ Not set'}`);
  console.log(`- ADMIN_PASSWORD: ${process.env.ADMIN_PASSWORD ? '✓ Set' : '✗ Not set'}`);
  console.log(`- USER_USERNAME: ${process.env.USER_USERNAME ? '✓ Set' : '✗ Not set'}`);
  console.log(`- USER_PASSWORD: ${process.env.USER_PASSWORD ? '✓ Set' : '✗ Not set'}`);
});
