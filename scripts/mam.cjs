const { execFileSync } = require('node:child_process')
execFileSync('./node_modules/.bin/mam', ['attendpro/student'], { cwd: require('node:path').resolve(__dirname,'..'), env: { ...process.env, MAM_PULL_DISABLED:'1' }, stdio:'inherit' })
