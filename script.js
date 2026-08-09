const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const STORAGE_KEYS = {
  users: 'reisGymUsers',
  currentUserId: 'reisGymCurrentUser',
};
let currentAccessCode = null;

// --- Cryptographic helpers (Web Crypto PBKDF2) ---
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function generateSaltBase64(length = 16) {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return arrayBufferToBase64(salt.buffer);
}

async function deriveKeyBase64(password, saltBase64, iterations = 100000) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = base64ToArrayBuffer(saltBase64);
  const derivedBits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: salt,
    iterations: iterations,
    hash: 'SHA-256',
  }, passKey, 256);
  return arrayBufferToBase64(derivedBits);
}

// Note: Client-side hashing improves safety against accidental plaintext exposure in localStorage,
// but it is NOT a replacement for a server-side authentication solution. For production, implement
// server-side salted hashing (bcrypt/argon2) behind HTTPS and avoid storing credential data in browsers.

function getFieldValue(form, name) {
  return form.querySelector(`[name="${name}"]`)?.value.trim() ?? '';
}
 
function setFeedback(element, message, type = 'success') {
  if (!element) return;
  element.textContent = message;
  element.classList.toggle('success', type === 'success');
  element.classList.toggle('error', type === 'error');
}
 
function validateEmail(email) {
  return !email || emailPattern.test(email);
}
 
function getUsers() {
  try {
    const saved = localStorage.getItem(STORAGE_KEYS.users);
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
}
 
function saveUsers(users) {
  localStorage.setItem(STORAGE_KEYS.users, JSON.stringify(users));
}

// --- Sincronização com o banco de dados na nuvem (Supabase) ---
// O localStorage continua sendo a fonte usada por toda a UI (rápido, síncrono).
// Essas funções espelham os dados no Supabase por trás, então o treino do aluno
// fica salvo de verdade e acessível de outro aparelho, não só no navegador local.

async function getSupabaseClient() {
  let tries = 0;
  while (!window.supabaseClient && tries < 20) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    tries += 1;
  }
  return window.supabaseClient || null;
}

async function syncUserToCloud(user) {
  try {
    const sb = await getSupabaseClient();
    if (!sb || !user) return;
    const { error } = await sb.from('reisgym_users').upsert({
      id: user.id,
      phone: user.phone || null,
      data: user,
      updated_at: new Date().toISOString(),
    });
    if (error) console.warn('Supabase upsert falhou:', error.message);
  } catch (e) {
    console.warn('Não foi possível sincronizar com o banco de dados na nuvem:', e);
  }
}

async function pullAllUsersFromCloud() {
  try {
    const sb = await getSupabaseClient();
    if (!sb) return [];
    const { data, error } = await sb.from('reisgym_users').select('data');
    if (error || !data) return [];
    return data.map((row) => row.data).filter(Boolean);
  } catch (e) {
    console.warn('Não foi possível buscar usuários na nuvem:', e);
    return [];
  }
}

// Roda uma vez ao carregar a página: traz pro localStorage qualquer cadastro
// que exista na nuvem mas ainda não exista neste navegador (ex: usuário criado
// em outro aparelho). Não sobrescreve dados locais mais recentes.
async function mergeCloudUsers() {
  try {
    const cloudUsers = await pullAllUsersFromCloud();
    if (!cloudUsers.length) return false;
    const localUsers = getUsers();
    const localIds = new Set(localUsers.map((u) => u.id));
    const merged = localUsers.slice();
    cloudUsers.forEach((cu) => {
      if (cu && cu.id && !localIds.has(cu.id)) {
        merged.push(cu);
      }
    });
    if (merged.length !== localUsers.length) {
      saveUsers(merged);
      return true;
    }
    return false;
  } catch (e) {
    console.warn('Erro ao mesclar usuários da nuvem:', e);
    return false;
  }
}
 
function findUserByContact(phone, email) {
  return getUsers().find((user) => {
    const matchPhone = phone && user.phone === phone;
    const matchEmail = email && user.email === email;
    return matchPhone || matchEmail;
  });
}
 
async function findUserByCredentials(phone, email, password) {
  if (!password) return null;
  const users = getUsers();
  const matchUser = users.find((user) => (phone && user.phone === phone) || (email && user.email === email));
  if (!matchUser || !matchUser.passwordSalt || !matchUser.passwordHash) return null;
  try {
    const derived = await deriveKeyBase64(password, matchUser.passwordSalt, matchUser.passwordIterations || 100000);
    if (derived === matchUser.passwordHash) return matchUser;
  } catch (e) {
    console.error('Erro ao validar senha:', e);
  }
  return null;
}
 
function saveUser(user) {
  const users = getUsers();
  const index = users.findIndex((existing) => existing.id === user.id);
  if (index >= 0) {
    users[index] = user;
  } else {
    users.push(user);
  }
  saveUsers(users);
  syncUserToCloud(user); // salva também no banco de dados na nuvem (não bloqueia a UI)
}
 
function getUserSchedule(user) {
  return user.schedule || [];
}
 
function addUserScheduleWorkout(user, workout) {
  user.schedule = user.schedule || [];
  user.schedule.push(workout);
  saveUser(user);
}
 
function getSelectedScheduleWorkoutId(user) {
  return localStorage.getItem(`${SELECTED_SCHEDULE_KEY}-${user.id}`);
}
 
function saveSelectedScheduleWorkout(user, workoutId) {
  localStorage.setItem(`${SELECTED_SCHEDULE_KEY}-${user.id}`, workoutId);
}
 
async function createUser({ name, phone, email, password, role = 'aluno' }) {
  try {
    const existing = findUserByContact(phone, email);
    if (existing) return null;

    // Ensure Web Crypto APIs are available before attempting to derive keys
    if (typeof crypto === 'undefined' || !crypto.subtle || !crypto.getRandomValues) {
      console.error('Web Crypto API não disponível no ambiente do cliente.');
      return null;
    }

    // generate salt and derive a password hash before saving
    const salt = generateSaltBase64(16);
    const iterations = 100000;
    let passwordHash = '';
    try {
      passwordHash = await deriveKeyBase64(password, salt, iterations);
    } catch (e) {
      console.error('Erro ao derivar senha:', e);
      return null;
    }

    const user = {
      id: `user-${Date.now()}`,
      name,
      phone,
      email,
      role: role || 'aluno',
      passwordHash,
      passwordSalt: salt,
      passwordIterations: iterations,
      focus: 'Força',
      schedule: [],
      createdAt: Date.now(),
    };

    saveUser(user);
    return user;
  } catch (e) {
    console.error('Erro inesperado em createUser:', e);
    return null;
  }
}
 
function setCurrentUser(user) {
  if (!user) return;
  localStorage.setItem(STORAGE_KEYS.currentUserId, user.id);
}
 
function getCurrentUser() {
  const userId = localStorage.getItem(STORAGE_KEYS.currentUserId);
  if (!userId) return null;
  return getUsers().find((user) => user.id === userId) || null;
}
 
function clearCurrentUser() {
  localStorage.removeItem(STORAGE_KEYS.currentUserId);
}
 
const WORKOUT_OPTIONS = {
  Força: [
    {
      id: 'forca-1',
      title: 'Treino de Força A',
      description: 'Movimentos básicos para construir base de força.',
      items: ['Agachamento livre 4x6', 'Supino reto 4x6', 'Remada curvada 4x8', 'Prancha 3x40s'],
    },
    {
      id: 'forca-2',
      title: 'Treino de Força B',
      description: 'Foco em levantamento de pesos e estabilidade.',
      items: ['Levantamento terra 4x5', 'Desenvolvimento com barra 4x6', 'Pull-over 3x10', 'Farmer carry 3x30s'],
    },
  ],
  Hipertrofia: [
    {
      id: 'hipertrofia-1',
      title: 'Treino de Hipertrofia A',
      description: 'Ondas de repetições para hipertrofia muscular.',
      items: ['Supino inclinado 4x10', 'Puxada alta 4x10', 'Crucifixo 3x12', 'Rosca direta 3x12'],
    },
    {
      id: 'hipertrofia-2',
      title: 'Treino de Hipertrofia B',
      description: 'Volume e intensidade para desenvolvimento.',
      items: ['Leg press 4x12', 'Stiff 4x10', 'Elevação lateral 3x15', 'Tríceps testa 3x12'],
    },
  ],
  Condicionamento: [
    {
      id: 'condicionamento-1',
      title: 'Treino Condicionamento A',
      description: 'Circuito com foco em resistência e mobilidade.',
      items: ['Circuito 20 min', 'Sprints 8x20s', 'Burpees 3x12', 'Abdominais 3x20'],
    },
    {
      id: 'condicionamento-2',
      title: 'Treino Condicionamento B',
      description: 'Alta intensidade com intervalos ativos.',
      items: ['Elíptico intervalado 15 min', 'Kettlebell swings 4x15', 'Flexões 3x15', 'Mountain climbers 3x30s'],
    },
  ],
  Emagrecimento: [
    {
      id: 'emagrecimento-1',
      title: 'Treino Emagrecimento A',
      description: 'Treino combinado de cardio e força leve.',
      items: ['Jumping jacks 4x30s', 'Leg press leve 3x15', 'Bicicleta 15 min', 'Prancha lateral 3x30s'],
    },
    {
      id: 'emagrecimento-2',
      title: 'Treino Emagrecimento B',
      description: 'HIIT curto para queima e condicionamento.',
      items: ['Corrida intervalada 12 min', 'Agachamento com salto 3x12', 'Abdominais 3x20', 'Prancha 3x40s'],
    },
  ],
};

const SELECTED_WORKOUT_KEY = 'reisGymSelectedWorkout';
const SELECTED_SCHEDULE_KEY = 'reisGymSelectedSchedule';
const WEEKDAYS = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo'];

// --- Exercise library: catálogo reutilizável de exercícios ---
const EXERCISE_LIBRARY = {
  Costas: [
    { id: 'ex-101', name: 'Remada curvada', defaultSets: '4x8', equipment: 'Barra livre' },
    { id: 'ex-102', name: 'Puxada alta (pulley)', defaultSets: '4x10', equipment: 'Polia' },
    { id: 'ex-103', name: 'Puxada frente supinada', defaultSets: '3x10', equipment: 'Polia' },
    { id: 'ex-104', name: 'Remada baixa (cabo)', defaultSets: '4x10', equipment: 'Cabo/Polia' },
    { id: 'ex-105', name: 'Remada unilateral com haltere', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-106', name: 'Pull-up (barra fixa)', defaultSets: '3x max', equipment: 'Barra fixa' },
    { id: 'ex-107', name: 'Levantamento terra', defaultSets: '4x5', equipment: 'Barra' },
    { id: 'ex-108', name: 'Face pull', defaultSets: '3x15', equipment: 'Polia/Corda' },
    { id: 'ex-109', name: 'Hiperextensão lombar', defaultSets: '3x15', equipment: 'Banco romano' },
    { id: 'ex-110', name: 'Remada cavalinho (T-bar)', defaultSets: '4x10', equipment: 'Barra T' },
    { id: 'ex-111', name: 'Remada máquina articulada', defaultSets: '3x12', equipment: 'Máquina' },
    { id: 'ex-112', name: 'Puxada neutra (pegada fechada)', defaultSets: '3x10', equipment: 'Polia' },
    { id: 'ex-113', name: 'Levantamento terra romeno', defaultSets: '4x8', equipment: 'Barra' },
    { id: 'ex-114', name: 'Pulldown com corda (straight-arm)', defaultSets: '3x15', equipment: 'Polia/Corda' },
    { id: 'ex-115', name: 'Remada invertida (australiana)', defaultSets: '3x max', equipment: 'Barra fixa baixa' },
  ],
  Peito: [
    { id: 'ex-201', name: 'Supino reto', defaultSets: '4x6', equipment: 'Barra' },
    { id: 'ex-202', name: 'Supino inclinado', defaultSets: '4x8', equipment: 'Barra' },
    { id: 'ex-203', name: 'Supino declinado', defaultSets: '3x8', equipment: 'Barra' },
    { id: 'ex-204', name: 'Supino com halteres', defaultSets: '4x10', equipment: 'Haltere' },
    { id: 'ex-205', name: 'Crucifixo reto', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-206', name: 'Crossover (cabo)', defaultSets: '3x15', equipment: 'Cabo/Polia' },
    { id: 'ex-207', name: 'Flexão de braço', defaultSets: '3x max', equipment: 'Corpo' },
    { id: 'ex-208', name: 'Peck deck (voador)', defaultSets: '3x12', equipment: 'Máquina' },
    { id: 'ex-209', name: 'Supino inclinado com halteres', defaultSets: '4x10', equipment: 'Haltere' },
    { id: 'ex-210', name: 'Crucifixo inclinado', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-211', name: 'Supino na máquina (smith)', defaultSets: '4x10', equipment: 'Smith machine' },
    { id: 'ex-212', name: 'Flexão com pés elevados', defaultSets: '3x max', equipment: 'Corpo' },
    { id: 'ex-213', name: 'Pullover com halteres', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-214', name: 'Paralelas (peitoral)', defaultSets: '3x max', equipment: 'Barras paralelas' },
  ],
  Perna: [
    { id: 'ex-301', name: 'Agachamento livre', defaultSets: '4x6', equipment: 'Barra' },
    { id: 'ex-302', name: 'Leg press', defaultSets: '4x10', equipment: 'Máquina' },
    { id: 'ex-303', name: 'Agachamento búlgaro', defaultSets: '3x10', equipment: 'Haltere' },
    { id: 'ex-304', name: 'Afundo (lunge)', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-305', name: 'Cadeira extensora', defaultSets: '3x15', equipment: 'Máquina' },
    { id: 'ex-306', name: 'Mesa flexora', defaultSets: '3x15', equipment: 'Máquina' },
    { id: 'ex-307', name: 'Stiff (posterior de coxa)', defaultSets: '4x8', equipment: 'Barra' },
    { id: 'ex-308', name: 'Cadeira adutora/abdutora', defaultSets: '3x15', equipment: 'Máquina' },
    { id: 'ex-309', name: 'Panturrilha em pé', defaultSets: '4x15', equipment: 'Máquina/Haltere' },
    { id: 'ex-310', name: 'Agachamento frontal', defaultSets: '4x6', equipment: 'Barra' },
    { id: 'ex-311', name: 'Agachamento hack', defaultSets: '4x10', equipment: 'Máquina hack' },
    { id: 'ex-312', name: 'Passada com halteres (walking lunge)', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-313', name: 'Panturrilha sentado', defaultSets: '4x15', equipment: 'Máquina' },
    { id: 'ex-314', name: 'Elevação pélvica unilateral', defaultSets: '3x12', equipment: 'Corpo' },
    { id: 'ex-315', name: 'Agachamento sissy', defaultSets: '3x12', equipment: 'Corpo' },
  ],
  Ombro: [
    { id: 'ex-401', name: 'Desenvolvimento com barra', defaultSets: '4x6', equipment: 'Barra' },
    { id: 'ex-402', name: 'Desenvolvimento com halteres', defaultSets: '4x8', equipment: 'Haltere' },
    { id: 'ex-403', name: 'Elevação lateral', defaultSets: '3x15', equipment: 'Haltere' },
    { id: 'ex-404', name: 'Elevação frontal', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-405', name: 'Remada alta', defaultSets: '3x12', equipment: 'Barra' },
    { id: 'ex-406', name: 'Crucifixo invertido', defaultSets: '3x15', equipment: 'Haltere' },
    { id: 'ex-407', name: 'Desenvolvimento Arnold', defaultSets: '3x10', equipment: 'Haltere' },
    { id: 'ex-408', name: 'Elevação lateral na polia', defaultSets: '3x15', equipment: 'Polia' },
    { id: 'ex-409', name: 'Desenvolvimento máquina', defaultSets: '4x10', equipment: 'Máquina' },
    { id: 'ex-410', name: 'Encolhimento de ombros (shrug)', defaultSets: '3x15', equipment: 'Haltere/Barra' },
    { id: 'ex-411', name: 'Crucifixo invertido na máquina', defaultSets: '3x15', equipment: 'Máquina' },
  ],
  Braço: [
    { id: 'ex-501', name: 'Rosca direta', defaultSets: '3x12', equipment: 'Barra' },
    { id: 'ex-502', name: 'Rosca alternada', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-503', name: 'Rosca martelo', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-504', name: 'Rosca scott', defaultSets: '3x10', equipment: 'Barra W' },
    { id: 'ex-505', name: 'Tríceps testa', defaultSets: '3x12', equipment: 'Barra' },
    { id: 'ex-506', name: 'Tríceps corda (polia)', defaultSets: '3x15', equipment: 'Polia' },
    { id: 'ex-507', name: 'Tríceps francês', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-508', name: 'Mergulho no banco (dips)', defaultSets: '3x max', equipment: 'Corpo' },
    { id: 'ex-509', name: 'Rosca 21', defaultSets: '3x21', equipment: 'Barra' },
    { id: 'ex-510', name: 'Rosca concentrada', defaultSets: '3x12', equipment: 'Haltere' },
    { id: 'ex-511', name: 'Tríceps coice (kickback)', defaultSets: '3x15', equipment: 'Haltere' },
    { id: 'ex-512', name: 'Tríceps banco (mergulho paralelas)', defaultSets: '3x max', equipment: 'Barras paralelas' },
    { id: 'ex-513', name: 'Rosca no cabo', defaultSets: '3x15', equipment: 'Polia' },
  ],
  Core: [
    { id: 'ex-601', name: 'Prancha', defaultSets: '3x40s', equipment: 'Corpo' },
    { id: 'ex-602', name: 'Prancha lateral', defaultSets: '3x30s', equipment: 'Corpo' },
    { id: 'ex-603', name: 'Abdominal supra', defaultSets: '3x20', equipment: 'Corpo' },
    { id: 'ex-604', name: 'Abdominal infra (elevação de pernas)', defaultSets: '3x15', equipment: 'Corpo' },
    { id: 'ex-605', name: 'Abdominal oblíquo', defaultSets: '3x20', equipment: 'Corpo' },
    { id: 'ex-606', name: 'Elevação de pernas na barra', defaultSets: '3x12', equipment: 'Barra fixa' },
    { id: 'ex-607', name: 'Rollout com roda abdominal', defaultSets: '3x10', equipment: 'Roda abdominal' },
    { id: 'ex-608', name: 'Abdominal na polia (crunch)', defaultSets: '3x15', equipment: 'Polia' },
    { id: 'ex-609', name: 'Mountain climber', defaultSets: '3x30s', equipment: 'Corpo' },
    { id: 'ex-610', name: 'Russian twist', defaultSets: '3x20', equipment: 'Peso/Corpo' },
    { id: 'ex-611', name: 'Prancha com elevação de perna', defaultSets: '3x30s', equipment: 'Corpo' },
  ],
  Glúteos: [
    { id: 'ex-701', name: 'Elevação pélvica (hip thrust)', defaultSets: '4x10', equipment: 'Barra' },
    { id: 'ex-702', name: 'Glúteo no cabo (coice)', defaultSets: '3x15', equipment: 'Cabo/Polia' },
    { id: 'ex-703', name: 'Abdução de quadril', defaultSets: '3x15', equipment: 'Máquina' },
    { id: 'ex-704', name: 'Agachamento sumô', defaultSets: '4x8', equipment: 'Haltere' },
    { id: 'ex-705', name: 'Cadeira abdutora', defaultSets: '3x15', equipment: 'Máquina' },
    { id: 'ex-706', name: 'Glúteo em 4 apoios (donkey kick)', defaultSets: '3x15', equipment: 'Corpo/Caneleira' },
    { id: 'ex-707', name: 'Passada lateral com elástico', defaultSets: '3x15', equipment: 'Elástico' },
  ],
  Cardio: [
    { id: 'ex-801', name: 'Corrida na esteira', defaultSets: '20 min', equipment: 'Esteira' },
    { id: 'ex-802', name: 'Bike ergométrica', defaultSets: '20 min', equipment: 'Bike' },
    { id: 'ex-803', name: 'Pular corda', defaultSets: '5x1 min', equipment: 'Corda' },
    { id: 'ex-804', name: 'HIIT no step/polichinelo', defaultSets: '8x30s', equipment: 'Corpo' },
    { id: 'ex-805', name: 'Elíptico', defaultSets: '20 min', equipment: 'Elíptico' },
    { id: 'ex-806', name: 'Remo ergométrico', defaultSets: '15 min', equipment: 'Remo' },
    { id: 'ex-807', name: 'Escada (stairmaster)', defaultSets: '15 min', equipment: 'Escada' },
    { id: 'ex-808', name: 'Corrida ao ar livre', defaultSets: '25 min', equipment: 'Nenhum' },
    { id: 'ex-809', name: 'Burpee', defaultSets: '5x10', equipment: 'Corpo' },
    { id: 'ex-810', name: 'Jumping jack', defaultSets: '5x30s', equipment: 'Corpo' },
  ],
  Posterior: [
    { id: 'ex-901', name: 'Levantamento terra romeno', defaultSets: '4x8', equipment: 'Barra' },
    { id: 'ex-902', name: 'Stiff com halteres', defaultSets: '4x10', equipment: 'Haltere' },
    { id: 'ex-903', name: 'Stiff com barra', defaultSets: '4x10', equipment: 'Barra' },
    { id: 'ex-904', name: 'Agachamento sumô', defaultSets: '4x8', equipment: 'Haltere' },
    { id: 'ex-905', name: 'Elevação pélvica unilateral', defaultSets: '3x12', equipment: 'Corpo' },
    { id: 'ex-906', name: 'Passada lateral com elástico', defaultSets: '3x15', equipment: 'Elástico' },
    { id: 'ex-907', name: 'Mesa flexora', defaultSets: '3x15', equipment: 'Máquina' },
    { id: 'ex-908', name: 'Good morning', defaultSets: '3x10', equipment: 'Barra' },
    { id: 'ex-909', name: 'Mesa flexora unilateral', defaultSets: '3x12', equipment: 'Máquina' },
    { id: 'ex-910', name: 'Glúteo-ham raise', defaultSets: '3x10', equipment: 'Banco GHR' },
    { id: 'ex-911', name: 'Nordic curl (flexora nórdica)', defaultSets: '3x8', equipment: 'Corpo' },
    { id: 'ex-912', name: 'Levantamento terra sumô', defaultSets: '4x6', equipment: 'Barra' },
    { id: 'ex-913', name: 'Cadeira flexora deitado', defaultSets: '3x15', equipment: 'Máquina' },
  ],
  Antebraço: [
    { id: 'ex-1001', name: 'Rosca de punho (wrist curl)', defaultSets: '3x15', equipment: 'Barra/Haltere' },
    { id: 'ex-1002', name: 'Rosca de punho invertida', defaultSets: '3x15', equipment: 'Barra/Haltere' },
    { id: 'ex-1003', name: 'Farmer carry (caminhada com peso)', defaultSets: '3x30m', equipment: 'Haltere/Kettlebell' },
    { id: 'ex-1004', name: 'Dead hang (pendurar na barra)', defaultSets: '3x max', equipment: 'Barra fixa' },
    { id: 'ex-1005', name: 'Rosca inversa (pegada pronada)', defaultSets: '3x12', equipment: 'Barra' },
    { id: 'ex-1006', name: 'Wrist roller (rolo de punho)', defaultSets: '3x max', equipment: 'Rolo de punho' },
    { id: 'ex-1007', name: 'Prensa de pinça (plate pinch)', defaultSets: '3x20s', equipment: 'Anilha' },
    { id: 'ex-1008', name: 'Extensor de mão (hand gripper)', defaultSets: '3x15', equipment: 'Hand gripper' },
  ],
};

// Ícones "bonequinho" — um corpo estilizado por grupo muscular, com a região trabalhada
// destacada em laranja (mesma ideia da imagem de referência que você mandou: silhueta +
// músculo em destaque). Desenho original em SVG, reaproveitado entre exercícios do mesmo grupo.
const BODY_BASE = '<circle cx="20" cy="6.5" r="4" class="body-part"/><rect x="14" y="11" width="12" height="15" rx="5" class="body-part"/><rect x="6.2" y="12" width="6" height="14" rx="3" class="body-part"/><rect x="27.8" y="12" width="6" height="14" rx="3" class="body-part"/><rect x="14" y="27" width="5" height="17" rx="2.5" class="body-part"/><rect x="21" y="27" width="5" height="17" rx="2.5" class="body-part"/>';

const GROUP_HIGHLIGHTS = {
  Peito: '<ellipse cx="20" cy="15.5" rx="6" ry="4" class="body-highlight"/>',
  Costas: '<rect x="14.5" y="11.5" width="11" height="14" rx="4.5" class="body-highlight" fill-opacity="0.55"/>',
  Ombro: '<circle cx="9.2" cy="13.5" r="3.4" class="body-highlight"/><circle cx="30.8" cy="13.5" r="3.4" class="body-highlight"/>',
  Braço: '<rect x="6.2" y="12" width="6" height="8.5" rx="3" class="body-highlight"/><rect x="27.8" y="12" width="6" height="8.5" rx="3" class="body-highlight"/>',
  Perna: '<rect x="14" y="27" width="5" height="10" rx="2.5" class="body-highlight"/><rect x="21" y="27" width="5" height="10" rx="2.5" class="body-highlight"/>',
  Glúteos: '<rect x="14" y="24.5" width="12" height="6" rx="3" class="body-highlight"/>',
  Core: '<rect x="15.7" y="18" width="8.6" height="7.5" rx="2.2" class="body-highlight"/>',
  Posterior: '<rect x="14" y="24.5" width="12" height="6" rx="3" class="body-highlight" fill-opacity="0.85"/><rect x="14" y="30" width="5" height="7" rx="2.5" class="body-highlight"/><rect x="21" y="30" width="5" height="7" rx="2.5" class="body-highlight"/>',
  Antebraço: '<rect x="6.2" y="19" width="6" height="7" rx="2.6" class="body-highlight"/><rect x="27.8" y="19" width="6" height="7" rx="2.6" class="body-highlight"/>',
  Cardio: '<circle cx="14" cy="8" r="4.2" class="body-part"/><line x1="14" y1="12" x2="20" y2="23" class="body-part" stroke-width="3"/><line x1="14" y1="15" x2="7" y2="10" class="body-part" stroke-width="3"/><line x1="14" y1="15" x2="24" y2="12" class="body-part" stroke-width="3"/><line x1="20" y1="23" x2="12" y2="30" class="body-part" stroke-width="3"/><line x1="12" y1="30" x2="16" y2="38" class="body-part" stroke-width="3"/><line x1="20" y1="23" x2="29" y2="19" class="body-part" stroke-width="3"/><line x1="29" y1="19" x2="34" y2="26" class="body-part" stroke-width="3"/>',
};

function getGroupIconSVG(group) {
  if (group === 'Cardio') {
    return `<svg viewBox="0 0 40 40" class="exercise-pictogram" aria-hidden="true">${GROUP_HIGHLIGHTS.Cardio}</svg>`;
  }
  const highlight = GROUP_HIGHLIGHTS[group] || '';
  return `<svg viewBox="0 0 40 46" class="exercise-pictogram" aria-hidden="true">${BODY_BASE}${highlight}</svg>`;
}

function getWorkoutTemplate(focus) {
  const templates = {
    Força: [
      'Treino A: agachamento, supino e remada',
      'Treino B: levantamento terra e desenvolvimento',
      'Treino C: braço e core',
    ],
    Hipertrofia: [
      'Treino A: peito, ombro e tríceps',
      'Treino B: costas, bíceps e pernas',
      'Treino C: glúteos e posteriores',
    ],
    Condicionamento: [
      'Circuito cardio + peso corporal',
      'Intervalado na esteira ou bike',
      'Treino funcional com mobilidade',
    ],
    Emagrecimento: [
      'Treino aeróbico moderado',
      'HIIT com alta intensidade',
      'Força leve com repetições altas',
    ],
  };
  return templates[focus] || templates.Força;
}

function getWorkoutOptionById(focus, workoutId) {
  return (WORKOUT_OPTIONS[focus] || []).find((option) => option.id === workoutId) || null;
}

function renderWorkoutOptions(user) {
  const workoutList = document.getElementById('workoutList');
  const selectedWorkoutId = localStorage.getItem(SELECTED_WORKOUT_KEY);
  if (!workoutList || !user) return;

  workoutList.innerHTML = '';
  const options = WORKOUT_OPTIONS[user.focus] || WORKOUT_OPTIONS.Força;

  options.forEach((option) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'workout-option';
    button.dataset.workoutId = option.id;
    button.innerHTML = `<strong>${option.title}</strong><span>${option.description}</span>`;
    if (option.id === selectedWorkoutId) {
      button.classList.add('active');
    }
    button.addEventListener('click', () => selectWorkout(option.id));
    workoutList.appendChild(button);
  });
}

function selectWorkout(workoutId) {
  const user = getCurrentUser();
  if (!user) return;
  localStorage.setItem(SELECTED_WORKOUT_KEY, workoutId);
  renderWorkoutOptions(user);
  const workout = getWorkoutOptionById(user.focus, workoutId);
  if (workout) {
    showSelectedWorkout(workout);
  }
}

function showSelectedWorkout(workout) {
  const title = document.getElementById('selectedWorkoutTitle');
  const description = document.getElementById('selectedWorkoutDescription');
  const details = document.getElementById('selectedWorkoutDetails');
  const items = document.getElementById('selectedWorkoutItems');
  const button = document.getElementById('startWorkoutButton');

  if (!title || !description || !details || !items || !button) return;

  title.textContent = workout.title || workout.name || 'Treino selecionado';
  description.textContent = workout.description || workout.notes || 'Detalhes do treino selecionado.';
  items.innerHTML = '';

  const detailItems = workout.items || [];
  if (workout.durationMinutes !== undefined) {
    detailItems.unshift(`Duração: ${workout.durationMinutes} min`);
  }
  if (workout.restMinutes !== undefined) {
    detailItems.unshift(`Pausa: ${workout.restMinutes} min`);
  }
  if (workout.day) {
    detailItems.unshift(`Dia: ${workout.day}`);
  }

  detailItems.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    items.appendChild(li);
  });

  details.classList.remove('hidden');
  button.classList.remove('hidden');
  button.textContent = 'Ir para o treino';
  button.onclick = () => {
    details.scrollIntoView({ behavior: 'smooth' });
  };
}

// Render exercise library UI for current user (called from updateDashboardForUser)
function renderExerciseLibrary(user) {
  const list = document.getElementById('exerciseList');
  const filter = document.getElementById('exerciseFilter');
  const search = document.getElementById('exerciseSearch');
  const draft = document.getElementById('draftWorkout');
  if (!list || !filter || !search || !draft) return;

  // populate filter options once
  if (filter.options.length <= 1) {
    Object.keys(EXERCISE_LIBRARY).forEach((group) => {
      const opt = document.createElement('option');
      opt.value = group;
      opt.textContent = group;
      filter.appendChild(opt);
    });
  }

  // helper to flatten and filter
  function getFilteredExercises() {
    const q = (search.value || '').toLowerCase().trim();
    const group = filter.value;
    let items = [];
    Object.keys(EXERCISE_LIBRARY).forEach((g) => {
      if (group && g !== group) return;
      EXERCISE_LIBRARY[g].forEach((ex) => items.push(Object.assign({}, ex, { group: g })));
    });
    if (q) items = items.filter((e) => e.name.toLowerCase().includes(q) || e.equipment.toLowerCase().includes(q));
    return items;
  }

  function refreshList() {
    list.innerHTML = '';
    const items = getFilteredExercises();
    if (items.length === 0) {
      list.innerHTML = '<div class="exercise-row">Nenhum exercício encontrado.</div>';
      return;
    }
    items.forEach((ex) => {
      const row = document.createElement('div');
      row.className = 'exercise-row';
      row.innerHTML = `<div class="exercise-row-main">${getGroupIconSVG(ex.group)}<div><strong>${ex.name}</strong><div class="meta">${ex.group} · ${ex.defaultSets} · ${ex.equipment}</div></div></div>`;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-secondary';
      btn.textContent = 'Adicionar';
      btn.addEventListener('click', () => handleAddExercise(ex));
      row.appendChild(btn);
      list.appendChild(row);
    });
  }

  search.addEventListener('input', refreshList);
  filter.addEventListener('change', refreshList);

  // draft handlers
  document.getElementById('saveDraftBtn')?.addEventListener('click', () => saveDraftAsSchedule(user));
  document.getElementById('clearDraftBtn')?.addEventListener('click', () => { draft._items = []; renderDraftWorkout(); });

  // initialize draft store on element
  if (!draft._items) draft._items = [];

  refreshList();
  renderDraftWorkout();
}

function handleAddExercise(ex) {
  // ask quick details (sets/reps/carga/obs) using prompts for now
  const defaultSets = ex.defaultSets || '';
  const sets = prompt(`Séries e repetições para ${ex.name}`, defaultSets) || defaultSets;
  const carga = prompt('Carga (ex: 60kg) — pode ficar em branco', '') || '';
  const obs = prompt('Observações (opcional)', '') || '';

  const draft = document.getElementById('draftWorkout');
  if (!draft) return;
  draft._items = draft._items || [];

  // prevent duplicate exercise in draft
  if (draft._items.find((it) => it.exerciseId === ex.id)) {
    alert('Exercício já adicionado ao treino em montagem.');
    return;
  }

  draft._items.push({ exerciseId: ex.id, name: ex.name, group: ex.group, sets, carga, obs });
  renderDraftWorkout();
}

function renderDraftWorkout() {
  const draft = document.getElementById('draftWorkout');
  if (!draft) return;
  draft._items = draft._items || [];
  if (draft._items.length === 0) {
    draft.innerHTML = 'Nenhum exercício adicionado ainda.';
    return;
  }
  draft.innerHTML = '';
  draft._items.forEach((it, idx) => {
    const div = document.createElement('div');
    div.className = 'draft-item';
    div.innerHTML = `<div class="info"><strong>${it.name}</strong><div style="font-size:0.85rem;color:#475569">${it.sets} · ${it.carga}${it.obs? ' · ' + it.obs : ''}</div></div>`;
    const actions = document.createElement('div');
    const btnRemove = document.createElement('button');
    btnRemove.className = 'btn btn-secondary';
    btnRemove.textContent = 'Remover';
    btnRemove.addEventListener('click', () => { draft._items.splice(idx,1); renderDraftWorkout(); });
    actions.appendChild(btnRemove);
    div.appendChild(actions);
    draft.appendChild(div);
  });
}

function saveDraftAsSchedule(user) {
  const draft = document.getElementById('draftWorkout');
  if (!draft || !user) return;
  draft._items = draft._items || [];
  if (draft._items.length === 0) {
    alert('Adicione ao menos um exercício antes de salvar.');
    return;
  }

  // ask for name and day
  const name = prompt('Nome do treino (ex: Treino personalizado A)', `Treino ${Date.now()}`) || `Treino ${Date.now()}`;
  const day = prompt('Dia da semana para salvar (Segunda, Terça, Quarta, Quinta, Sexta, Sábado, Domingo)', 'Segunda') || 'Segunda';
  const restMinutes = parseInt(prompt('Pausa entre séries (minutos)', '2') || '2', 10) || 2;
  const durationMinutes = parseInt(prompt('Duração estimada (minutos)', '45') || '45', 10) || 45;

  const workout = {
    id: `schedule-${Date.now()}`,
    name,
    day,
    restMinutes,
    durationMinutes,
    notes: draft._items.map((it) => `${it.name} — ${it.sets}${it.carga ? ' · ' + it.carga : ''}${it.obs? ' · ' + it.obs : ''}`).join('; '),
    exercises: draft._items.slice(),
    createdAt: Date.now(),
  };

  addUserScheduleWorkout(user, workout);
  // clear draft and re-render schedule
  draft._items = [];
  renderDraftWorkout();
  expandedScheduleDay = day;
  renderWorkoutSchedule(user);
  closeWorkoutBuilderModal();
  alert('Treino salvo na sua semana.');
}

let expandedScheduleDay = null;

function openWorkoutBuilderModal() {
  const modal = document.getElementById('workoutBuilderModal');
  if (!modal) return;
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeWorkoutBuilderModal() {
  const modal = document.getElementById('workoutBuilderModal');
  if (!modal) return;
  modal.classList.add('hidden');
  document.body.style.overflow = '';
}

function renderWorkoutSchedule(user) {
  const scheduleContainer = document.getElementById('workoutSchedule');
  if (!scheduleContainer || !user) return;

  const schedule = getUserSchedule(user);
  scheduleContainer.innerHTML = '';

  if (!expandedScheduleDay) {
    const jsDay = new Date().getDay();
    expandedScheduleDay = WEEKDAYS[jsDay === 0 ? 6 : jsDay - 1];
  }

  const jsDayToday = new Date().getDay();
  const todayName = WEEKDAYS[jsDayToday === 0 ? 6 : jsDayToday - 1];

  WEEKDAYS.forEach((day) => {
    const dayWorkouts = schedule.filter((item) => item.day === day);
    const isOpen = expandedScheduleDay === day;

    const daySection = document.createElement('div');
    daySection.className = 'day-block' + (isOpen ? ' open' : '') + (dayWorkouts.length ? ' has-workouts' : '') + (day === todayName ? ' today' : '');

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'day-block-header';
    header.setAttribute('aria-expanded', String(isOpen));
    header.innerHTML = `
      <span class="day-block-name">${day}</span>
      <span class="day-block-count">${dayWorkouts.length ? dayWorkouts.length + (dayWorkouts.length === 1 ? ' treino' : ' treinos') : 'Sem treino'}</span>
      <svg class="day-block-chevron" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
    `;
    header.addEventListener('click', () => {
      expandedScheduleDay = isOpen ? null : day;
      renderWorkoutSchedule(user);
    });

    const listWrap = document.createElement('div');
    listWrap.className = 'day-list-wrap';

    const dayList = document.createElement('div');
    dayList.className = 'day-list';

    if (dayWorkouts.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'day-empty';
      empty.textContent = 'Sem treino nesse dia ainda.';
      dayList.appendChild(empty);
    } else {
      dayWorkouts.forEach((workout) => {
        const itemWrap = document.createElement('div');
        itemWrap.className = 'schedule-item-wrap';

        const item = document.createElement('div');
        item.className = 'schedule-item';
        if (workout.completedAt) item.classList.add('completed');
        item.dataset.workoutId = workout.id;
        item.innerHTML = `<div class="schedule-main"><strong>${workout.name}</strong><span>Pausa ${workout.restMinutes} min · ${workout.durationMinutes || 0} min</span></div>`;

        const actions = document.createElement('div');
        actions.className = 'schedule-actions';

        const btnComplete = document.createElement('button');
        btnComplete.type = 'button';
        btnComplete.className = 'complete';
        btnComplete.title = 'Marcar como concluído';
        btnComplete.textContent = workout.completedAt ? 'Desmarcar' : 'Concluído';
        btnComplete.addEventListener('click', (e) => { e.stopPropagation(); toggleCompleteWorkout(user, workout.id); });

        const btnEdit = document.createElement('button');
        btnEdit.type = 'button';
        btnEdit.className = 'edit';
        btnEdit.title = 'Editar treino';
        btnEdit.textContent = 'Editar';
        btnEdit.addEventListener('click', (e) => { e.stopPropagation(); editScheduledWorkout(user, workout.id); });

        const btnDelete = document.createElement('button');
        btnDelete.type = 'button';
        btnDelete.className = 'delete';
        btnDelete.title = 'Excluir treino';
        btnDelete.textContent = 'Excluir';
        btnDelete.addEventListener('click', (e) => { e.stopPropagation(); deleteScheduledWorkout(user, workout.id); });

        actions.appendChild(btnComplete);
        actions.appendChild(btnEdit);
        actions.appendChild(btnDelete);

        itemWrap.appendChild(item);
        itemWrap.appendChild(actions);
        item.addEventListener('click', () => selectScheduledWorkout(user, workout.id));
        dayList.appendChild(itemWrap);
      });
    }

    listWrap.appendChild(dayList);
    daySection.appendChild(header);
    daySection.appendChild(listWrap);
    scheduleContainer.appendChild(daySection);
  });
}

function selectScheduledWorkout(user, workoutId) {
  const workout = (getUserSchedule(user) || []).find((entry) => entry.id === workoutId);
  if (!workout) return;
  saveSelectedScheduleWorkout(user, workoutId);
  renderWorkoutSchedule(user);
  showScheduledWorkout(workout);
  document.getElementById('selectedWorkoutCard')?.scrollIntoView({ behavior: 'smooth' });
}

function deleteScheduledWorkout(user, workoutId) {
  if (!user) return;
  const confirmed = confirm('Excluir este treino da sua agenda?');
  if (!confirmed) return;
  user.schedule = (user.schedule || []).filter((w) => w.id !== workoutId);
  saveUser(user);
  if (user.id === getCurrentUser()?.id) {
    renderWorkoutSchedule(user);
    loadDashboard();
  }
}

function editScheduledWorkout(user, workoutId) {
  const workout = (user.schedule || []).find((w) => w.id === workoutId);
  if (!workout) return;
  // simple prompt-based edit: name, day, rest, duration, notes
  const newName = prompt('Nome do treino', workout.name) || workout.name;
  const newDay = prompt('Dia da semana', workout.day) || workout.day;
  const newRest = prompt('Pausa (minutos)', String(workout.restMinutes || 2)) || String(workout.restMinutes || 2);
  const newDuration = prompt('Duração estimada (minutos)', String(workout.durationMinutes || 45)) || String(workout.durationMinutes || 45);
  const newNotes = prompt('Descrição / exercícios', workout.notes || workout.description || '') || workout.notes || workout.description || '';

  workout.name = newName;
  workout.day = newDay;
  workout.restMinutes = Number(newRest);
  workout.durationMinutes = Number(newDuration);
  workout.notes = newNotes;
  workout.updatedAt = Date.now();

  saveUser(user);
  if (user.id === getCurrentUser()?.id) {
    renderWorkoutSchedule(user);
    showScheduledWorkout(workout);
  }
}

function toggleCompleteWorkout(user, workoutId) {
  const workout = (user.schedule || []).find((w) => w.id === workoutId);
  if (!workout) return;
  if (workout.completedAt) {
    // unmark
    delete workout.completedAt;
  } else {
    workout.completedAt = Date.now();
    // add to history if needed — here we keep completedAt on the workout itself
  }
  saveUser(user);
  if (user.id === getCurrentUser()?.id) {
    renderWorkoutSchedule(user);
    // update stats
    updateDashboardForUser(user);
  }
}
function showScheduledWorkout(workout) {
  const title = document.getElementById('selectedWorkoutTitle');
  const description = document.getElementById('selectedWorkoutDescription');
  const details = document.getElementById('selectedWorkoutDetails');
  const items = document.getElementById('selectedWorkoutItems');
  const button = document.getElementById('startWorkoutButton');

  if (!title || !description || !details || !items || !button) return;

  title.textContent = `${workout.day}: ${workout.name}`;
  description.textContent = workout.notes || workout.description || 'Detalhes do treino programado.';
  items.innerHTML = '';

  const detailsList = [
    `Pausa: ${workout.restMinutes} min`,
    `Dia: ${workout.day}`,
    workout.notes ? `O que fazer: ${workout.notes}` : 'Sem descrição adicional.',
  ];

  detailsList.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    items.appendChild(li);
  });

  details.classList.remove('hidden');
  button.classList.remove('hidden');
  button.textContent = 'Ir para este treino';
  button.onclick = () => {
    details.scrollIntoView({ behavior: 'smooth' });
  };
}

function loadSelectedWorkout(user) {
  const selectedScheduleId = getSelectedScheduleWorkoutId(user);
  if (selectedScheduleId) {
    const schedule = getUserSchedule(user);
    const workout = schedule.find((entry) => entry.id === selectedScheduleId);
    if (workout) {
      selectScheduledWorkout(user, workout.id);
      return;
    }
  }

  const workoutId = localStorage.getItem(SELECTED_WORKOUT_KEY);
  if (!user) return;
  const workout = getWorkoutOptionById(user.focus, workoutId);
  if (workout) {
    showSelectedWorkout(workout);
  } else {
    const details = document.getElementById('selectedWorkoutDetails');
    if (details) {
      details.classList.add('hidden');
    }
  }
}

function handleWorkoutFormSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const user = getCurrentUser();
  if (!user) return;

  const name = getFieldValue(form, 'workoutName');
  const day = getFieldValue(form, 'workoutDay');
  const restMinutes = getFieldValue(form, 'workoutPause');
  const durationMinutes = getFieldValue(form, 'workoutDuration');
  const notes = getFieldValue(form, 'workoutDescription');

  if (!name || !day || !restMinutes || !durationMinutes) {
    return;
  }

  const workout = {
    id: `schedule-${Date.now()}`,
    name,
    day,
    restMinutes: Number(restMinutes),
    durationMinutes: Number(durationMinutes),
    notes,
    createdAt: Date.now(),
  };

  addUserScheduleWorkout(user, workout);
  expandedScheduleDay = day;
  renderWorkoutSchedule(user);
  form.reset();
  closeWorkoutBuilderModal();
  selectScheduledWorkout(user, workout.id);
}

function updateDashboardForUser(user) {
  const userName = document.getElementById('dashboardUserName');
  const userMeta = document.getElementById('dashboardUserMeta');
  const focusValue = document.getElementById('dashboardFocus');
  const planCount = document.getElementById('dashboardPlanCount');
  const goalText = document.getElementById('goalText');
  const workoutList = document.getElementById('dashboardWorkoutList');
  const streakValue = document.getElementById('streakValue');
  const progressChart = document.getElementById('progressChart');
  const personalPanel = document.getElementById('personalPanel');

  if (!userName || !userMeta || !focusValue || !planCount || !goalText || !workoutList) return;

  userName.textContent = user.name;
  userMeta.textContent = user.email ? `Login: ${user.email}` : `WhatsApp: ${user.phone}`;
  focusValue.textContent = user.focus || 'Força';
  planCount.textContent = (WORKOUT_OPTIONS[user.focus] || WORKOUT_OPTIONS.Força).length;
  goalText.textContent = `Plano de treino focado em ${user.focus.toLowerCase()} para seus próximos treinos.`;

  const dashboardWorkoutList = document.getElementById('dashboardWorkoutList');
  if (dashboardWorkoutList) {
    dashboardWorkoutList.innerHTML = '';
    getWorkoutTemplate(user.focus).forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      dashboardWorkoutList.appendChild(li);
    });
  }

  renderWorkoutOptions(user);
  renderExerciseLibrary(user);
  renderWorkoutSchedule(user);
  loadSelectedWorkout(user);
  highlightFocusButton(user.focus || 'Força');

  // compute and show streak + progress
  if (streakValue) {
    const streakCount = computeStreak(user);
    streakValue.textContent = String(streakCount);
    const streakTextEl = document.getElementById('streakText');
    if (streakTextEl) {
      streakTextEl.classList.toggle('streak-active', streakCount > 0);
    }
  }
  if (progressChart) {
    renderProgressChart(user, progressChart);
  }

  // personal panel visible only for role 'personal'
  if (personalPanel) {
    if (user.role === 'personal') {
      personalPanel.style.display = '';
      renderPersonalPanel();
    } else {
      personalPanel.style.display = 'none';
    }
  }
}
 
function loadDashboard() {
  const user = getCurrentUser();
  const dashboardContent = document.getElementById('dashboardContent');
  const dashboardPlaceholder = document.getElementById('dashboardPlaceholder');

  if (!dashboardContent || !dashboardPlaceholder) return;

  if (!user) {
    dashboardContent.classList.add('hidden');
    dashboardPlaceholder.classList.remove('hidden');
    return;
  }

  dashboardPlaceholder.classList.add('hidden');
  dashboardContent.classList.remove('hidden');
  updateDashboardForUser(user);
}
 
function handleContactSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const feedback = document.getElementById('formFeedback');
  const name = getFieldValue(form, 'name');
  const email = getFieldValue(form, 'email');
  const message = getFieldValue(form, 'message');

  if (!name || !email || !message) {
  setFeedback(feedback, 'Por favor, preencha todos os campos.', 'error');
  return;
  }

  if (!validateEmail(email)) {
  setFeedback(feedback, 'Informe um e-mail válido para continuar.', 'error');
  return;
  }

  setFeedback(feedback, 'Obrigado! Sua mensagem foi enviada com sucesso.', 'success');
  form.reset();
}

async function handleSignupSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const feedback = document.getElementById('signupFeedback');
  const name = getFieldValue(form, 'signupName');
  const phone = getFieldValue(form, 'signupPhone');
  const email = getFieldValue(form, 'signupEmail');
  const password = getFieldValue(form, 'signupPassword');

  console.info('Signup attempt:', { name, phone, email });

  if (!name || !phone || !password) {
    setFeedback(feedback, 'Informe nome, telefone e uma forma de acesso para continuar.', 'error');
    return;
  }

  if (!validateEmail(email)) {
    setFeedback(feedback, 'Informe um e-mail válido ou deixe o campo em branco.', 'error');
    return;
  }

  const role = getFieldValue(form, 'signupRole') || 'aluno';

  // Feature-detect Web Crypto early and give a helpful message if missing
  if (typeof crypto === 'undefined' || !crypto.subtle || !crypto.getRandomValues) {
    console.error('Web Crypto indisponível na inscrição');
    setFeedback(feedback, 'Seu navegador não oferece os recursos de segurança necessários (Web Crypto). Atualize o navegador (Chrome/Firefox/Edge) e tente novamente.', 'error');
    return;
  }

  try {
    const user = await createUser({ name, phone, email, password, role });
    if (!user) {
      const existing = findUserByContact(phone, email);
      if (existing) {
        setFeedback(feedback, 'Já existe um usuário com este telefone ou e-mail.', 'error');
      } else {
        setFeedback(feedback, 'Não foi possível criar o cadastro. Verifique seu navegador e tente novamente.', 'error');
      }
      return;
    }

    setCurrentUser(user);
    setFeedback(feedback, 'Cadastro criado com sucesso! Você já está no painel.', 'success');
    form.reset();
    // small delay to let UI update then redirect
    setTimeout(() => { window.location.href = 'dashboard.html'; }, 150);
  } catch (err) {
    console.error('Erro ao criar usuário (async):', err);
    setFeedback(feedback, 'Erro ao criar cadastro. Tente novamente mais tarde.', 'error');
  }
}

function handleRequestCode(event) {
  // keep existing behavior (generate code) but ensure a user exists and do not expose the code in UI

  event.preventDefault();
  const form = event.currentTarget.closest('form');
  const feedback = document.getElementById('loginFeedback');
  const phone = getFieldValue(form, 'loginPhone');
  const email = getFieldValue(form, 'loginEmail');

  if (!phone && !email) {
    setFeedback(feedback, 'Informe o telefone/WhatsApp ou o e-mail para receber o código.', 'error');
    return;
  }

  if (!validateEmail(email)) {
    setFeedback(feedback, 'Informe um e-mail válido ou deixe o campo em branco.', 'error');
    return;
  }

  const user = findUserByContact(phone, email);
  if (!user) {
    setFeedback(feedback, 'Cadastro não encontrado. Crie uma conta primeiro.', 'error');
    return;
  }

  // Generate code and (in a real app) send via server-side SMS/email provider.
  currentAccessCode = String(Math.floor(1000 + Math.random() * 9000));
  // Do NOT expose the code in UI in normal operation — here we show a message that a code was sent,
  // but for safety we don't print the code itself. In production the server would send it.
  if (email) {
    setFeedback(feedback, `Código de acesso enviado para o e-mail ${email}. Verifique sua caixa de entrada.`, 'success');
  } else {
    setFeedback(feedback, `Código de acesso enviado para o WhatsApp/telefone. Verifique suas mensagens.`, 'success');
  }

  form.querySelector('[name="loginCode"]')?.focus();
  // For local testing only: log the code in console (do not use in production)
  console.info('DEBUG: access code (local testing only):', currentAccessCode);
}

function handleLogout() {
  clearCurrentUser();
  loadDashboard();
  window.location.hash = '#cadastro';
}

function setTrainingFocus(focus) {
  const user = getCurrentUser();
  if (!user) return;
  user.focus = focus;
  saveUser(user);
  updateDashboardForUser(user);
  highlightFocusButton(focus);
  showFocusConfirmation(focus);
}

function highlightFocusButton(focus) {
  document.querySelectorAll('.focus-option').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.focus === focus);
  });
}

function showFocusConfirmation(focus) {
  const panel = document.getElementById('focusConfirm');
  if (!panel) return;
  const count = (WORKOUT_OPTIONS[focus] || []).length;
  panel.innerHTML = `<strong>${focus} selecionado</strong><span>${count} treino${count === 1 ? '' : 's'} disponíve${count === 1 ? 'l' : 'is'} com esse foco agora.</span>`;
  panel.classList.remove('open');
  // força reflow para reiniciar a transição mesmo clicando no mesmo foco de novo
  void panel.offsetWidth;
  panel.classList.add('open');
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const feedback = document.getElementById('loginFeedback');
  const phone = getFieldValue(form, 'loginPhone');
  const email = getFieldValue(form, 'loginEmail');
  const code = getFieldValue(form, 'loginCode');
  const password = getFieldValue(form, 'loginPassword');

  console.info('Login attempt:', { phone, email, hasPassword: Boolean(password), hasCode: Boolean(code) });

  try {
    if ((!phone && !email) || (!code && !password)) {
      setFeedback(feedback, 'Informe telefone/e-mail e senha ou código para entrar.', 'error');
      return;
    }

    if (!validateEmail(email)) {
      setFeedback(feedback, 'Informe um e-mail válido ou deixe o campo em branco.', 'error');
      return;
    }

    // when password is provided, validate via async derived-key comparison
    let user = null;
    if (password) {
      try {
        user = await findUserByCredentials(phone, email, password);
        if (!user) {
          // pode ser um cadastro feito em outro aparelho que ainda não chegou aqui — tenta buscar na nuvem antes de desistir
          await mergeCloudUsers();
          user = await findUserByCredentials(phone, email, password);
        }
      } catch (e) {
        console.error('Erro ao verificar credenciais (deriveKey):', e);
      }
      if (!user) {
        setFeedback(feedback, 'Telefone/e-mail ou senha incorretos.', 'error');
        return;
      }
    } else {
      user = findUserByContact(phone, email);
      if (!currentAccessCode || code !== currentAccessCode) {
        setFeedback(feedback, 'Código incorreto ou ainda não foi enviado. Clique em “Receber código”.', 'error');
        return;
      }
      if (!user) {
        setFeedback(feedback, 'Cadastro não encontrado. Crie uma conta primeiro.', 'error');
        return;
      }
    }

    setCurrentUser(user);
    setFeedback(feedback, 'Login realizado com sucesso! Bem-vindo à Reis Gym.', 'success');
    form.reset();
    currentAccessCode = null;
    // small delay so the success message is visible then redirect
    setTimeout(() => { window.location.href = 'dashboard.html'; }, 150);
  } catch (err) {
    console.error('Erro inesperado no login:', err);
    setFeedback(feedback, 'Erro ao processar login. Tente novamente mais tarde.', 'error');
  }
}

// --------- Additional helpers: streak, progress, personal panel ---------

function startOfWeek(d) {
  const date = new Date(d);
  const day = date.getDay();
  // treat Monday as first day: day 1 => Monday. JS: 0 (Sun) .. 6 (Sat)
  const diff = (day === 0) ? -6 : 1 - day;
  date.setDate(date.getDate() + diff);
  date.setHours(0,0,0,0);
  return date;
}

function formatDateKey(d) {
  const date = new Date(d);
  return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}`;
}

function computeStreak(user) {
  const schedule = getUserSchedule(user) || [];
  const completedDates = new Set();
  schedule.forEach((w) => {
    if (w.completedAt) {
      completedDates.add(formatDateKey(w.completedAt));
    }
  });
  let streak = 0;
  const today = new Date();
  for (let i = 0; i < 365; i++) {
    const check = new Date();
    check.setDate(today.getDate() - i);
    const key = formatDateKey(check);
    if (completedDates.has(key)) streak++; else break;
  }
  return streak;
}

function renderProgressChart(user, container) {
  if (!container) return;
  container.innerHTML = '';
  const now = new Date();
  const weekStart = startOfWeek(now);
  const days = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(weekStart);
    d.setDate(weekStart.getDate() + i);
    days.push(d);
  }
  const schedule = getUserSchedule(user) || [];
  const todayKey = formatDateKey(now);

  const wrapper = document.createElement('div');
  wrapper.className = 'progress-wrapper';

  const totalPlanned = schedule.length;
  const totalCompleted = schedule.filter((w) => w.completedAt).length;
  const pct = totalPlanned > 0 ? Math.round((totalCompleted / totalPlanned) * 100) : 0;

  const summary = document.createElement('div');
  summary.className = 'progress-summary';
  if (totalPlanned === 0) {
    summary.innerHTML = `
      <div class="progress-summary-text">
        <span class="progress-summary-label">Nenhum treino agendado ainda essa semana</span>
      </div>
      <div class="progress-bar-track"><div class="progress-bar-fill" style="width:0%"></div></div>
    `;
  } else {
    summary.innerHTML = `
      <div class="progress-summary-text">
        <span class="progress-summary-count">${totalCompleted}/${totalPlanned}</span>
        <span class="progress-summary-label">treinos concluídos essa semana</span>
      </div>
      <div class="progress-bar-track"><div class="progress-bar-fill" style="width:${pct}%"></div></div>
    `;
  }
  wrapper.appendChild(summary);

  const chart = document.createElement('div');
  chart.className = 'week-tracker';

  days.forEach((d) => {
    const dayName = WEEKDAYS[d.getDay() === 0 ? 6 : d.getDay() - 1];
    const dateKey = formatDateKey(d);
    const plannedCount = schedule.filter((w) => w.day === dayName).length;
    const completedCount = schedule.filter((w) => w.completedAt && formatDateKey(w.completedAt) === dateKey).length;
    const isToday = dateKey === todayKey;
    const isCompleted = plannedCount > 0 && completedCount >= plannedCount;
    const isPartial = completedCount > 0 && completedCount < plannedCount;

    const dayEl = document.createElement('div');
    dayEl.className = 'week-day';

    const circle = document.createElement('div');
    circle.className = 'week-day-circle';
    if (isCompleted) circle.classList.add('completed');
    else if (isPartial) circle.classList.add('partial');
    else if (plannedCount > 0) circle.classList.add('planned');
    if (isToday) circle.classList.add('today');
    circle.title = plannedCount > 0
      ? `Planejado: ${plannedCount} · Concluído: ${completedCount}`
      : 'Sem treino planejado';

    if (isCompleted) {
      circle.innerHTML = '<svg viewBox="0 0 24 24" class="week-check" aria-hidden="true"><path d="M5 13l4 4L19 7" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    } else if (plannedCount > 0) {
      circle.innerHTML = `<span class="week-day-count">${completedCount}/${plannedCount}</span>`;
    } else {
      circle.innerHTML = '<span class="week-day-dot"></span>';
    }

    const label = document.createElement('div');
    label.className = 'week-day-label';
    label.textContent = d.toLocaleDateString('pt-BR', { weekday: 'short' }).replace('.', '');
    const dateLabel = document.createElement('div');
    dateLabel.className = 'week-day-date';
    dateLabel.textContent = String(d.getDate()).padStart(2, '0');

    dayEl.appendChild(circle);
    dayEl.appendChild(label);
    dayEl.appendChild(dateLabel);
    chart.appendChild(dayEl);
  });

  wrapper.appendChild(chart);

  if (totalPlanned === 0) {
    const empty = document.createElement('p');
    empty.className = 'progress-empty-hint';
    empty.textContent = 'Você ainda não tem treinos nessa semana — adicione um na agenda para começar a acompanhar seu progresso.';
    wrapper.appendChild(empty);
  }

  container.appendChild(wrapper);
}

function renderPersonalPanel() {
  const list = document.getElementById('personalList');
  if (!list) return;
  list.innerHTML = '';
  const students = getUsers().filter((u) => u && u.role !== 'personal');

  const countEl = document.getElementById('personalStudentCount');
  if (countEl) countEl.textContent = String(students.length);

  const searchInput = document.getElementById('personalSearch');
  const term = (searchInput?.value || '').trim().toLowerCase();
  const users = term
    ? students.filter((u) => (u.name || '').toLowerCase().includes(term) || (u.phone || '').includes(term))
    : students;

  if (users.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'small-muted';
    empty.textContent = term ? 'Nenhum aluno encontrado com essa busca.' : 'Nenhum aluno cadastrado ainda.';
    list.appendChild(empty);
    return;
  }

  users.forEach((u) => {
    if (!u) return;
    // skip personals themselves in the list or show them too
    const row = document.createElement('div');
    row.className = 'personal-row';
    row.innerHTML = `<div><strong>${u.name}</strong><div style="font-size:0.85rem;color:#475569">${u.phone || ''} ${u.email ? '· ' + u.email : ''} · ${u.role || 'aluno'}</div></div>`;

    const actions = document.createElement('div');
    const btnEdit = document.createElement('button');
    btnEdit.className = 'btn btn-secondary';
    btnEdit.textContent = 'Editar';
    btnEdit.addEventListener('click', () => {
      const newName = prompt('Nome do aluno', u.name) || u.name;
      const newPhone = prompt('Telefone', u.phone || '') || u.phone || '';
      const newEmail = prompt('E-mail', u.email || '') || u.email || '';
      u.name = newName;
      u.phone = newPhone;
      u.email = newEmail;
      saveUser(u);
      renderPersonalPanel();
    });

    const btnView = document.createElement('button');
    btnView.className = 'btn btn-primary';
    btnView.textContent = 'Ver agenda';
    btnView.addEventListener('click', () => {
      // load the selected user's schedule into the current view for inspection
      // set as read-only view: simply render their schedule and details
      const dashboardPlaceholder = document.getElementById('dashboardPlaceholder');
      const dashboardContent = document.getElementById('dashboardContent');
      if (dashboardContent && dashboardPlaceholder) {
        dashboardPlaceholder.classList.add('hidden');
        dashboardContent.classList.remove('hidden');
      }
      // render other user's schedule in main area by temporarily treating them as current user for display only
      renderWorkoutOptions(u);
      renderWorkoutSchedule(u);
      loadSelectedWorkout(u);
      // show name header
      const userName = document.getElementById('dashboardUserName');
      const userMeta = document.getElementById('dashboardUserMeta');
      if (userName) userName.textContent = `${u.name} (visualização)`;
      if (userMeta) userMeta.textContent = u.email ? `Login: ${u.email}` : `WhatsApp: ${u.phone}`;
    });

    const btnDelete = document.createElement('button');
    btnDelete.className = 'btn';
    btnDelete.textContent = 'Remover';
    btnDelete.addEventListener('click', () => {
      if (!confirm(`Remover o usuário ${u.name}? Esta ação não pode ser desfeita.`)) return;
      deleteUser(u.id);
      renderPersonalPanel();
    });

    actions.appendChild(btnView);
    actions.appendChild(btnEdit);
    // prevent removing yourself
    if (u.id !== getCurrentUser().id) actions.appendChild(btnDelete);
    row.appendChild(actions);
    list.appendChild(row);
  });
}

function deleteUser(userId) {
  const users = getUsers().filter((u) => u.id !== userId);
  localStorage.setItem(STORAGE_KEYS.users, JSON.stringify(users));
}

function toggleMobileMenu() {
  const mobileMenuButton = document.querySelector('.mobile-menu-toggle');
  const mainNav = document.querySelector('.main-nav');
  if (!mobileMenuButton || !mainNav) return;

  const isOpen = mainNav.classList.toggle('nav-open');
  mobileMenuButton.textContent = isOpen ? 'Fechar' : 'Menu';
  mobileMenuButton.setAttribute('aria-expanded', String(isOpen));
  mainNav.setAttribute('aria-hidden', String(!isOpen));
}

function closeMobileMenu() {
  const mobileMenuButton = document.querySelector('.mobile-menu-toggle');
  const mainNav = document.querySelector('.main-nav');
  if (!mobileMenuButton || !mainNav || !mainNav.classList.contains('nav-open')) return;

  mainNav.classList.remove('nav-open');
  mainNav.setAttribute('aria-hidden', 'false');
  mobileMenuButton.textContent = 'Menu';
  mobileMenuButton.setAttribute('aria-expanded', 'false');
}

function switchAccessPanel(button) {
  const targetId = button.dataset.target;

  document.querySelectorAll('.access-tab').forEach((tab) => {
    const isActive = tab === button;
    tab.classList.toggle('active', isActive);
    tab.setAttribute('aria-selected', String(isActive));
    tab.setAttribute('tabindex', isActive ? '0' : '-1');
  });

  document.querySelectorAll('.access-panel').forEach((panel) => {
    const isActive = panel.id === targetId;
    panel.classList.toggle('active', isActive);
    panel.setAttribute('aria-hidden', String(!isActive));
  });
}

function setupRevealAnimations() {
  const elements = document.querySelectorAll(
  '.hero-grid, .hero-actions, .section-header, .card, .pricing-card, .about-copy > *, .business-panel, .testimonial-card, .contact-grid > *, .map-frame'
  );

  if (!elements.length) return;

  elements.forEach((element, index) => {
  element.classList.add('reveal');
  element.style.setProperty('--reveal-delay', `${Math.min(index * 0.05, 0.8)}s`);
  });

  const observer = new IntersectionObserver(
  (entries, observerRef) => {
   entries.forEach((entry) => {
     if (entry.isIntersecting) {
       entry.target.classList.add('reveal-visible');
       observerRef.unobserve(entry.target);
     }
   });
  },
  { rootMargin: '0px 0px -10% 0px', threshold: 0.15 }
  );

  elements.forEach((element) => observer.observe(element));
}

const THEME_KEY = 'reisGymTheme';

function getCurrentTheme() {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function applyThemeToggleLabel() {
  const btn = document.getElementById('themeToggle');
  if (!btn) return;
  const theme = getCurrentTheme();
  btn.textContent = theme === 'light' ? '☀️ Claro' : '🌙 Escuro';
}

function setupThemeToggle() {
  applyThemeToggleLabel();
  const btn = document.getElementById('themeToggle');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const next = getCurrentTheme() === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch (e) {
      console.warn('Não foi possível salvar a preferência de tema:', e);
    }
    applyThemeToggleLabel();
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();
  setupRevealAnimations();

  const signupForm = document.getElementById('studentSignupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', handleSignupSubmit);
  }

  const loginForm = document.getElementById('studentLoginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLoginSubmit);
    loginForm.querySelector('.request-code-btn')?.addEventListener('click', handleRequestCode);
  }

  const contactForm = document.getElementById('contactForm');
  if (contactForm) {
    contactForm.addEventListener('submit', handleContactSubmit);
  }

  document.querySelector('.mobile-menu-toggle')?.addEventListener('click', toggleMobileMenu);
  document.querySelectorAll('.main-nav a').forEach((link) => {
    link.addEventListener('click', closeMobileMenu);
  });

  document.querySelectorAll('.access-tab').forEach((button) => {
    button.addEventListener('click', () => switchAccessPanel(button));
  });

  document.querySelectorAll('.focus-option').forEach((button) => {
    button.addEventListener('click', () => setTrainingFocus(button.dataset.focus));
  });
 
  document.getElementById('logoutButton')?.addEventListener('click', handleLogout);
  document.getElementById('workoutForm')?.addEventListener('submit', handleWorkoutFormSubmit);

  document.getElementById('personalSearch')?.addEventListener('input', () => renderPersonalPanel());

  document.getElementById('openWorkoutBuilderBtn')?.addEventListener('click', openWorkoutBuilderModal);
  document.getElementById('closeWorkoutBuilderBtn')?.addEventListener('click', closeWorkoutBuilderModal);
  document.getElementById('workoutBuilderModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'workoutBuilderModal') closeWorkoutBuilderModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeWorkoutBuilderModal();
  });
 
  // Carrega o painel imediatamente com o que já está salvo localmente (rápido, sem espera).
  loadDashboard();
  // Em paralelo, busca a nuvem; se trouxer algo novo (ex: cadastro feito em outro aparelho),
  // recarrega o painel só então — sem travar a primeira renderização.
  mergeCloudUsers().then((changed) => {
    if (changed) loadDashboard();
  });

  // Admin utility: export current users to a downloadable JSON backup and then clear all user data from localStorage.
  // Trigger by adding ?resetUsers=1 to the URL (e.g., index.html?resetUsers=1). This is destructive — backup download is attempted first.
  async function exportUsersBackupAndClear() {
    try {
      const users = getUsers();
      const payload = { exportedAt: new Date().toISOString(), users };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const ts = new Date();
      const fn = `reisgym-users-backup-${ts.getFullYear()}${String(ts.getMonth()+1).padStart(2,'0')}${String(ts.getDate()).padStart(2,'0')}-${String(ts.getHours()).padStart(2,'0')}${String(ts.getMinutes()).padStart(2,'0')}${String(ts.getSeconds()).padStart(2,'0')}.json`;
      const a = document.createElement('a');
      a.href = url;
      a.download = fn;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      // give the browser a moment to start download
      setTimeout(() => {
        // Clear keys used for users and current session
        localStorage.removeItem(STORAGE_KEYS.users);
        localStorage.removeItem(STORAGE_KEYS.currentUserId);
        // remove selected workout keys (global and per-user)
        try {
          Object.keys(localStorage).forEach((k) => {
            if (k && (k.startsWith(SELECTED_WORKOUT_KEY) || k.startsWith(SELECTED_SCHEDULE_KEY) || k.startsWith('reisGymSelected'))) {
              localStorage.removeItem(k);
            }
          });
        } catch (e) { /* ignore */ }
        alert('Backup gerado e todos os cadastros foram removidos do armazenamento local.');
        // reload to reflect cleared state
        window.location.href = window.location.pathname;
      }, 600);
    } catch (err) {
      console.error('Erro ao exportar e limpar usuários:', err);
      alert('Falha ao gerar backup e/ou limpar cadastros. Veja o console para detalhes.');
    }
  }

  // If the URL contains resetUsers=1, perform backup+clear automatically.
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.get('resetUsers') === '1') {
      // brief confirmation to avoid accidental resets when user opens a shared link
      if (confirm('Confirma gerar backup dos cadastros e resetar todos os cadastros no site? (ação irreversível no browser)')) {
        exportUsersBackupAndClear();
      }
    }
  } catch (e) {
    console.warn('Não foi possível verificar parâmetros de URL para resetUsers.');
  }
});
